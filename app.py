# coding=utf-8
import os
import tornado
import tornado.web
from tornado.options import define, options


from handlers import (
    IndexHandler,
    LoginHandler,
    LogoutHandler,
    WeiboLoginHandler,
    WeiboCallBackHandler,
    RegisterHandler,
    CardPayHandler,
    BankPayHandler,
    PayCallBackHandler,
    PayResultHandler,
)
import setting


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", IndexHandler),
            (r"/login/$", LoginHandler),
            (r'/logout/',LogoutHandler),
            (r"/login/weibo/$", WeiboLoginHandler),
            (r"/login/weibo/callback/$", WeiboCallBackHandler),
            (r"/register/$", RegisterHandler),
            (r"/pay/card/$", CardPayHandler),
            (r"/pay/bank/$", BankPayHandler),
            (r"/pay/callback/$", PayCallBackHandler),
            (r"/pay/result/$", PayResultHandler),
        ]
        settings = dict(
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "statics"),
            xsrf_cookies=True,
            cookie_secret='3E9Q5kDp8fqadGZsYKbuijcUCzRFrVJm',
            login_url="/auth/login",
            debug=True,
        )
        super(Application, self).__init__(handlers, **settings)


def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(setting.SERVER_PORT)
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()