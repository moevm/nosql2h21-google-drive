#!/usr/bin/env python3

import sys
import asyncio
import signal

from aiohttp import web

import jinja2
import aiohttp_jinja2

import motor.motor_asyncio as aiomotor

MONGO_HOST = 'localhost'
MONGO_PORT = 27017

MONGO_DBNAME = 'helloworld'
MONGO_COLLNAME = 'messages'

routes = web.RouteTableDef()

@routes.get('/hello')
@aiohttp_jinja2.template('hello.html')
async def _(req):
    client = aiomotor.AsyncIOMotorClient(MONGO_HOST, MONGO_PORT)
    db = client[MONGO_DBNAME]
    coll = db[MONGO_COLLNAME]

    what = req.query.getone("what", "world")

    res = await coll.find_one({"what": what})
    if res is None:
        reason = f"No text for what={what!r}"
        raise web.HTTPBadRequest(
            reason=reason,
            text=aiohttp_jinja2.render_string(
                'error.html',
                req,
                { 'reason': reason },
            ),
            content_type='text/html',
        )

    return {
        'what': what,
        'text': res['text'],
    }

@routes.get('/')
@aiohttp_jinja2.template('index.html')
def route_root(req):
    return {
        'title': "Index",
    }

def make_app():
    app = web.Application()
    app.add_routes(routes)

    aiohttp_jinja2.setup(
        app,
        loader=jinja2.FileSystemLoader('templates'),
        autoescape=jinja2.select_autoescape(['html', 'xml']),
    )

    return app

if __name__ == '__main__':
    web.run_app(
        make_app(),
        host='127.0.0.1',
        port=8080,
    )
