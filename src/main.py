#!/usr/bin/env python3

import sys
import json
import uuid
import asyncio
import queue
import datetime
from enum import IntEnum, auto

from multidict import CIMultiDict

import alog

import aiohttp
import aiohttp.web as aioweb
from yarl import URL

import jinja2
import aiohttp_jinja2

import gaggle

import motor.motor_asyncio as aiomotor

from math import trunc


MONGO_HOST = 'localhost'
MONGO_PORT = 27017

# MONGO_DBNAME = 'gdrivesorter'
MONGO_DBNAME = 'fetch-files'


DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%f%z'


def hostport(url):
    return f"{url.host}:{url.port}"


def pick_redirect_uri(req, uris):
    hp = hostport(req.url)
    for u in uris:
        if hostport(URL(u)) == hp:
            return u
    raise aioweb.HTTPInternalServerError(
        text=f'No redirect URL for host {hp}'
    )


def minjson(s):
    return json.dumps(json.loads(s))


# Return files collection name for user
# If work=True, returns tmp collection name for updates
def make_files_collname(user, work=False):
    prefix = 'tmp_files' if work else 'files'
    uid = user['_id']
    return f"{prefix}_{uid}"


async def query_oauth_authorize(req, scopes, dest_uri=None):
    sec = req.app['client_secret_json']['web']
    db = req.app['db']

    assert not isinstance(scopes, str)

    _uuid = uuid.uuid4()
    suuid = str(_uuid)
    uri = sec['auth_uri']
    query = {
        'client_id':     sec['client_id'],
        'redirect_uri':  pick_redirect_uri(req, sec['redirect_uris']),
        'response_type': 'code',
        'scope':         ' '.join(scopes),
        'access_type':   'online',
        'state':         suuid,
    }

    dest = str(dest_uri or req.url.relative())

    await db.sessions.update_one(
        {'_id': suuid},
        {
            '$set': {'path': dest},
            '$unset': {'user_id': ""},
        },
        upsert=True,
    )

    url = URL(uri).with_query(query)

    return aioweb.HTTPFound(location=url)


async def query_oauth_access(req, auth_code):
    sec = req.app['client_secret_json']['web']

    assert isinstance(auth_code, str)

    uri = sec['token_uri']
    payload = {
        'client_id':     sec['client_id'],
        'client_secret': sec['client_secret'],
        'code':          auth_code,
        'grant_type':    'authorization_code',
        'redirect_uri':  pick_redirect_uri(req, sec['redirect_uris']),
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(uri, data=payload) as resp:
            if not resp.ok:
                resp.content.set_exception(None)
                errinfo = minjson(resp.content.read_nowait().decode())
                alog.error(f"{resp.status} {resp.reason} {errinfo}")
                return None
            return await resp.json()


GOOGLE_API_SCOPES = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/drive.readonly',
]


async def user_info(req):
    if sid := req.cookies.get('session_id', None):
        db = req.app['db']
        if sess := await db.sessions.find_one({'_id': sid}):
            # TODO: check that session isn’t expired

            user_id = sess['user_id']
            if user := await db.users.find_one({'_id': user_id}):
                return user
            else:
                await db.sessions.delete_one({'_id': sid})

    raise await query_oauth_authorize(req, GOOGLE_API_SCOPES)


async def user_update_access(req, uid, info, r, new=False):
    tok = r['access_token']
    exp = r['expires_in']

    # Note: we don’t know the base of the expires_in field, so we
    # cannot calculate the actual time the session expires. So we
    # just take a large enough margin: half the expiry time.

    dt = exp // 2
    now = datetime.datetime.utcnow()
    expdt = now + datetime.timedelta(seconds=dt)

    db = req.app['db']
    await db.users.update_one(
        {'_id': uid},
        {
            '$set': {
                'access_token': r['access_token'],
                'expires_at': expdt,
                **info
            },
        },
        upsert=new,
    )


async def user_request_update_access(req, user):
    auth_code = user['auth_code']
    userinfo = {k: v for k, v in user.items() if k != '_id'}

    if r := await query_oauth_access(req, auth_code):
        user_update_access(req, user['_id'], userinfo, r, new=False)
        return r['access_token']

    raise aioweb.HTTPInternalServerError(
        text=f'Failed to query access token from Google',
    )


async def user_access(req, user):
    if exp := user['expires_at']:
        now = datetime.datetime.utcnow()
        if now < exp:
            return user['access_token']
    return await user_request_update_access(req, user)


def gaggle_client_for_token(req, tok, session):
    sec = req.app['client_secret_json']['web']
    return gaggle.Client(
        session=session,
        token=tok,
        client_id=sec['client_id'],
        client_secret=sec['client_secret'],
    )

async def gaggle_client_for_user(req, user, session):
    tok = await user_access(req, user)
    return gaggle_client_for_token(req, tok, session)

async def do_logout(db, sid):
    # Max-Age=0 expires the cookie immediately
    cookie_headers = CIMultiDict([
        ('Set-Cookie', f"session_id={sid}; Max-Age=0"),
    ])

    await db.sessions.delete_one({'_id': sid})

    return cookie_headers


routes = aioweb.RouteTableDef()

@routes.get('/')
@aiohttp_jinja2.template('index.html')
async def _(req):
    sid = req.cookies.get('session_id', None)
    if sid is None:
        raise aioweb.HTTPFound(location='/login')

    # TODO: redirect to root dir page

    user = await user_info(req)
    coll = req.app['db'][make_files_collname(user)]
    nfiles = await coll.count_documents({})

    return {
        'title': "Index",
        'session_id': sid,
        'user': user,
        'nfiles': nfiles,
    }


async def childrenFiles(db, user_id, file_id):
    if files := await db[f'files_{user_id}'].find_one({'_id': int(file_id)}):
        return files


@routes.get('/main')
@aiohttp_jinja2.template('main.html')
async def _(req):
    sid = req.cookies.get('session_id', None)
    user = (await user_info(req)) if sid else None

    file_id = req.rel_url.query.get("id")
    if file_id == None:
        file_id = 0

    db = req.app['db']
    # получение файлов по id
    files = await childrenFiles(db, user['_id'], file_id)
    if files:
        files = files['children']
        for i in files:
            i['file_id'] = trunc(i['file_id'])

    return {
        'name': user['name'],
        'files': files
    }

@routes.get('/dologin')
async def _(req):
    raise await query_oauth_authorize(req, GOOGLE_API_SCOPES,
                                      dest_uri='/')

@routes.get('/login')
@aiohttp_jinja2.template('login.html')
async def _(req):
    if sid := req.cookies.get('session_id', None):
        cookie_headers = await do_logout(req.app['db'], sid)
        # Basically, log out and try again
        raise aioweb.HTTPFound(
            location='/login',
            headers=cookie_headers,
        )

    return {
        'url': "/dologin",
    }


@routes.get('/logout')
async def logout_route(req):
    if sid := req.cookies.get('session_id', None):
        cookie_headers = await do_logout(req.app['db'], sid)
    else:
        cookie_headers = {}
    raise aioweb.HTTPFound(
        location='/',
        headers=cookie_headers,
    )

routes.post('/logout')(logout_route)

@routes.get('/whoami')
@aiohttp_jinja2.template('whoami.html')
async def _(req):
    async with aiohttp.ClientSession() as session:
        user = await user_info(req)
        client = await gaggle_client_for_user(req, user, session)
        resp = await client.people('v1').people.get(
            resourceName='people/me',
            personFields='names,emailAddresses',
        )
        if not resp.ok:
            resp.content.set_exception(None)
            errinfo = resp.content.read_nowait().decode()
            raise aioweb.HTTPInternalServerError(
                text=(f'API server returned status {resp.status} {resp.reason}'
                      + errinfo),
            )

        j = await resp.json()

    return {
        'resource_name': j['resourceName'],
        'names': [
            n['displayName']
            for n in j['names']
        ],
        'emails': [
            e['value']
            for e in j['emailAddresses']
        ],
    }


class PaginatedRequestError:
    def __init__(self, resp):
        self.resp = resp

async def request_with_pagination(
        method, req_dict, data_key,
        resp_key='nextPageToken',
        req_key='pageToken',
):
    res = []
    req_copy = {**req_dict}
    while True:
        resp = await method(**req_copy)
        if not resp.ok:
            raise PaginatedRequestError(resp)

        j = await resp.json()
        res.extend(j[data_key])

        if tok := j.get(resp_key):
            req_copy[req_key] = tok
        else:
            break

    return res


def filter_gdrive_files(files):
    root_children = []
    root_ids = set()
    ftab = {
        f['id']: (
            {**f, 'children': []}
            if f['mimeType'] == 'application/vnd.google-apps.folder'
            else f
        ) for f in files
    }

    for k, v in ftab.items():
        pars = v.get('parents')
        if pars is None:
            continue
        par_id = pars[0]
        if p := ftab.get(par_id):
            p['children'].append(k)
        else:
            root_children.append(k)
            root_ids.add(par_id)

    bad_ids = [k for k, v in ftab.items() if not v.get('parents')]
    qidx = 0
    while qidx < len(bad_ids):
        bad_ids.extend(ftab[bad_ids[qidx]].get('children', []))
        qidx += 1

    bad_ids = set(bad_ids)
    files_filtered = [v for k, v in ftab.items() if k not in bad_ids]

    alog.debug(f'bad ids: {len(bad_ids)}, ok: {len(files_filtered)}')

    if len(root_ids) != 1:
        alog.warning(f'len(root_ids)!=1: {root_ids!r}')

    return [
        {
            'id': (list(root_ids) or [None])[0],
            'mimeType': 'application/vnd.google-apps.folder',
            'children': root_children,
        },
        *files_filtered,
    ]


class FileType(IntEnum):
    REGULAR = auto()
    DIRECTORY = auto()
    GOOGLE_WORKSPACE = auto()
    UNKNOWN = auto()

def mime_to_file_type(mime):
    if mime == 'application/vnd.google-apps.folder':
        return FileType.DIRECTORY
    elif mime in ('application/vnd.google-apps.drive-sdk',
                  'application/vnd.google-apps.shortcut'):
        return FileType.UNKNOWN
    elif mime.startswith('application/vnd.google-apps.'):
        return FileType.GOOGLE_WORKSPACE
    else:
        return FileType.REGULAR

class AccessMode(IntEnum):
    RO = auto()
    COMMENT = auto()
    RW = auto()

def role_to_access_mode(role):
    if role == 'reader':
        return AccessMode.RO
    elif role == 'commenter':
        return AccessMode.COMMENT
    else:
        return AccessMode.RW

def perm_to_name_email(perm):
    return {
        'name': perm['displayName'],
        'email': perm.get('emailAddress'),
    }

def file_from_gdrive(f):
    anyone_perm = None
    owner_perm = None
    other_perms = []

    for perm in f['permissions']:
        if perm['type'] == 'anyone':
            assert anyone_perm is None
            anyone_perm = perm
        elif perm['role'] == 'owner':
            assert owner_perm is None
            owner_perm = perm
        else:
            # Note: non-user permissions are also saved
            other_perms.append(perm)

    return {
        'google_id': f['id'],
        'name': f['name'],
        'type': mime_to_file_type(f['mimeType']),
        'mime': f['mimeType'],
        'owner': (None if owner_perm is None
                  else perm_to_name_email(owner_perm)),
        'shared_with': [
            {
                **perm_to_name_email(perm),
                'access': role_to_access_mode(perm['role']),
            }
            for perm in other_perms
        ],
        'size': int(s) if (s := f.get('size', None)) else None,
        'shared_via_link': (None if anyone_perm is None
                            else role_to_access_mode(anyone_perm['role'])),
        'mtime': datetime.datetime.strptime(f['modifiedTime'], DATETIME_FORMAT),
        'parent': ps[0] if (ps := f.get('parents')) else None,
        'children': f.get('children'),
        'upper_dirs': None,
    }


def child_record(f):
    return {
        'file_id': f['_id'],
        **{
            k: f[k]
           for k in ['google_id', 'name', 'type', 'mime',
                     'size', 'owner', 'shared_with', 'mtime']
        }
    }

def handle_references(files):
    ftab = {f['google_id']: f for f in files}

    for f in files:
        if p := f['parent']:
            f['parent'] = ftab[p]['_id']
        if ch := f['children']:
            f['children'] = [
                child_record(ftab[ch])
                for ch in ch
            ]


def handle_upper_dirs(files):
    files[0]['upper_dirs'] = []

    s = [0]
    while s:
        s, t = [], s
        for x in t:
            rec = files[x]
            ud = [
                *rec['upper_dirs'],
                {
                    'id': x,
                    'name': rec['name'],
                },
            ]
            if ch := rec['children']:
                for c in ch:
                    cid = c['file_id']
                    files[cid]['upper_dirs'] = ud
                    s.append(cid)


async def recreate_files_collection(req, user):
    async with aiohttp.ClientSession() as session:
        client = await gaggle_client_for_user(req, user, session)

        props = ",".join([
            "id", "name", "parents", "mimeType",
            "permissions",
            "size", "modifiedTime",
        ])
        greq = {
            'corpora': 'user',
            'spaces': 'drive',
            'fields': f'files({props}),nextPageToken',
        }

        files_src = await request_with_pagination(
            client.drive('v3').files.list, greq, 'files')

        files = filter_gdrive_files(files_src)

        root = files[0]
        resp = await client.drive('v3').files.get(
            fileId=root['id'],
            fields=props,
        )
        assert resp.ok
        files[0] = {
            **(await resp.json()),
            'children': root['children'],
        }

    db = req.app['db']
    collname = make_files_collname(user)

    new_collname = make_files_collname(user, True)
    new_coll = db[new_collname]
    await new_coll.delete_many({})

    objs = [
        {
            '_id': i,
            **file_from_gdrive(f),
        }
        for i, f in enumerate(files)
    ]

    handle_references(objs)
    handle_upper_dirs(objs)

    await new_coll.insert_many(objs)

    await db.drop_collection(collname)
    await new_coll.rename(collname)


@routes.get('/reload')
async def _(req):
    user = await user_info(req)
    await recreate_files_collection(req, user)

    raise aioweb.HTTPFound(location='/')


@routes.get('/get')
async def _(req):
    user = await user_info(req)
    fid = int(req.query.getone('id', 0))
    collname = make_files_collname(user)

    class DatetimeJSONEncoder(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, datetime.datetime):
                return o.strftime(DATETIME_FORMAT)
            else:
                return super().default(o)

    if j := await req.app['db'][collname].find_one({'_id': fid}):
        return aioweb.Response(
            text=DatetimeJSONEncoder(indent=2, ensure_ascii=False).encode(j),
        )
    else:
        raise aioweb.HTTPNotFound(
            text=f"No file with id {fid}",
        )


@routes.get('/autherror')
async def _(req):
    err = req.query.getone('error', '(error missing)')
    return aioweb.Response(
        text=f'App authentication failed: {err}',
    )

@routes.get('/google-oauth-return')
async def _(req):
    db = req.app['db']

    if state := req.query.getone('state', None):
        sess = await db.sessions.find_one(
            {'_id': state},
            projection={'path': 1},
        )
        if sess is None or 'path' not in sess:
            alog.warning('/google-oauth-return: have state but no record or no original url')
            raise aioweb.HTTPBadRequest(
                text='Invalid request: unknown session id',
            )
        else:
            original_url = sess['path']
    else:
        alog.warning('/google-oauth-return but no state')
        original_url = None

    if 'error' in req.query:
        raise aioweb.HTTPFound(location='/autherror')

    auth_code = req.query.getone('code', None)
    if not auth_code:
        raise aioweb.HTTPInternalServerError(
            text='WTF, no error and no code from Google\'s auth',
        )

    r = await query_oauth_access(req, auth_code)
    if not r:
        raise aioweb.HTTPInternalServerError(
            text=f'Failed to query access token from Google',
        )

    async with aiohttp.ClientSession() as session:
        sec = req.app['client_secret_json']['web']
        people = gaggle.Client(
            session=session,
            token=r['access_token'],
            client_id=sec['client_id'],
            client_secret=sec['client_secret'],
        ).people('v1')
        resp = await people.people.get(
            resourceName='people/me',
            personFields='metadata,names',
        )
        if not resp.ok:
            resp.content.set_exception(None)
            errinfo = resp.content.read_nowait().decode()
            raise aioweb.HTTPInternalServerError(
                text=(f'API server returned status {resp.status} {resp.reason}'
                      + errinfo),
            )

        j = await resp.json()
        uid = j['metadata']['sources'][0]['id']
        info = {
            'auth_code': auth_code,
            'name': j['names'][0]['displayName'],
        }

    await user_update_access(req, uid, info, r, new=True)

    # why generate another UUID when we can just reuse the old one?
    sid = state

    await db.sessions.update_one(
        {'_id': sid},
        {
            '$set': {'user_id': uid},
            '$unset': {'path': ""},
        },
        upsert=True,
    )

    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie

    # Note: sid is a UUID string, so its character set is [0-9a-f-].
    # TODO: configure Max-Age
    cookie_headers = CIMultiDict([
        ('Set-Cookie', f"session_id={sid}; Max-Age=3600"),
    ])

    if original_url is None:
        return aioweb.Response(
            text='Ok',
            headers=cookie_headers,
        )

    return aioweb.HTTPFound(
        location=original_url,
        headers=cookie_headers,
    )


async def make_app(argv):
    app = aioweb.Application()
    app.add_routes(routes)

    with open('secrets/client-secret.json') as f:
        app['client_secret_json'] = json.load(f)

    app['dbclient'] = aiomotor.AsyncIOMotorClient(MONGO_HOST, MONGO_PORT)
    app['db'] = app['dbclient'][MONGO_DBNAME]

    aiohttp_jinja2.setup(
        app,
        loader=jinja2.FileSystemLoader('templates'),
        autoescape=jinja2.select_autoescape(['html', 'xml']),
    )

    return app


if __name__ == '__main__':
    aioweb.run_app(
        make_app(sys.argv),
        host='127.0.0.1',
        port=8085,
    )
