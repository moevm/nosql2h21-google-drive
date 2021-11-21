#!/usr/bin/env python3

import sys
import json
import uuid
import asyncio
import queue
import datetime

from multidict import CIMultiDict

import alog

import aiohttp
import aiohttp.web as aioweb
from yarl import URL

import jinja2
import aiohttp_jinja2

import gaggle

import motor.motor_asyncio as aiomotor


MONGO_HOST = 'localhost'
MONGO_PORT = 27017

MONGO_DBNAME = 'gdrivesorter'


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


async def query_oauth_authorize(req, scopes):
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

    await db.sessions.update_one(
        {'_id': suuid},
        {
            '$set': {'path': str(req.url.relative())},
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


async def user_update_access(req, user, r, new=False):
    uid = user['_id']
    auth_code = user['auth_code']
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
                'auth_code': auth_code,
                'access_token': r['access_token'],
                'expires_at': expdt,
            },
        },
        upsert=new,
    )


async def user_request_update_access(req, user):
    auth_code = user['auth_code']

    if r := await query_oauth_access(req, auth_code):
        user_update_access(req, user, r, new=False)
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


async def gaggle_client(req, session):
    user = await user_info(req)
    tok = await user_access(req, user)
    sec = req.app['client_secret_json']['web']
    return gaggle.Client(
        session=session,
        token=tok,
        client_id=sec['client_id'],
        client_secret=sec['client_secret'],
    )


routes = aioweb.RouteTableDef()

@routes.get('/')
@aiohttp_jinja2.template('index.html')
async def _(req):
    return {
        'title': "Index",
        'session_id': req.cookies.get('session_id', None),
    }

@routes.get('/logout')
async def logout_route(req):
    if sid := req.cookies.get('session_id', None):
        # Max-Age=0 expires the cookie immediately
        cookie_headers = CIMultiDict([
            ('Set-Cookie', f"session_id={sid}; Max-Age=0"),
        ])

        db = req.app['db']
        await db.sessions.delete_one({'_id': sid})
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
        client = await gaggle_client(req, session)
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

@routes.get('/listdrives')
@aiohttp_jinja2.template('drives.html')
async def _(req):
    async with aiohttp.ClientSession() as session:
        client = await gaggle_client(req, session)

        drives = []

        greq = {}
        while True:
            gresp = await client.drive('v3').drives.list(**greq)
            if not gresp.ok:
                gresp.content.set_exception(None)
                errinfo = gresp.content.read_nowait().decode()
                raise aioweb.HTTPInternalServerError(
                    text=(f'API server returned status {gresp.status} {gresp.reason} {errinfo}'),
                )

            j = await gresp.json()

            drives.extend(j['drives'])

            if npt := j.get('nextPageToken'):
                greq['pageToken'] = npt
            else:
                break

    return {
        'drives': drives,
    }

@routes.get('/listfiles')
@aiohttp_jinja2.template('files.html')
async def _(req):
    n_files = int(n) if (n := req.query.get('n')) else 10000
    do_filter = not bool(req.query.get('nofilter'))

    async with aiohttp.ClientSession() as session:
        client = await gaggle_client(req, session)

        files = []

        greq = {
            'corpora': 'user',
            'spaces': 'drive',
            'fields': 'files(id,name,parents,mimeType,shared,sharedWithMeTime),nextPageToken',
        }
        while len(files) < n_files:
            gresp = await client.drive('v3').files.list(**greq)
            if not gresp.ok:
                gresp.content.set_exception(None)
                errinfo = gresp.content.read_nowait().decode()
                raise aioweb.HTTPInternalServerError(
                    text=(f'API server returned status {gresp.status} {gresp.reason} {errinfo}'),
                )

            j = await gresp.json()

            files.extend(j['files'])

            if npt := j.get('nextPageToken'):
                greq['pageToken'] = npt
            else:
                break

    if do_filter:
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

        files = [
            {
                'id': (list(root_ids) or [None])[0],
                'mimeType': 'application/vnd.google-apps.folder',
                'children': root_children,
            },
            *files_filtered,
        ]

    return {
        'files': [
            json.dumps(f, indent=2, ensure_ascii=False)
            for f in files
        ],
    }

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
            personFields='metadata',
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

    await user_update_access(req, {
        '_id': uid,
        'auth_code': auth_code,
    }, r, new=True)

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
        ('Set-Cookie', f"session_id={sid}; Max-Age=60"),
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
