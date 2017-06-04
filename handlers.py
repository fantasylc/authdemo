from urllib.parse import urlencode
import logging
import time
import tornado.web
from tornado import gen
from tornado.httpclient import AsyncHTTPClient
from tornado import escape
import setting
from models import User, Order, WeiBoOauth
import hmac
import re
import hashlib
import datetime
logger = logging.getLogger(__name__)


class BaseHandler(tornado.web.RequestHandler):


    def get_current_user(self):
        email = self.get_secure_cookie("email", "")
        uid = self.get_secure_cookie("uid", "")
        print(email)
        if not any([email, uid]):
            return None
        if email:
            users = User.objects(email=email.decode('utf-8'))
            if not users:
                return None
            return users[0]
        elif uid:
            users = WeiBoOauth.objects(uid=int(uid))
            if not users:
                return None
            return users[-1]

class IndexHandler(BaseHandler):
    def get(self):
        self.render("index.html", user=self.current_user, content="")


class LoginHandler(BaseHandler):
    def get(self):
        if self.current_user:
            self.redirect('/')
        else:
            self.render('login.html', err_msg="")

    def post(self, *args, **kwargs):
        email = self.get_argument("email")
        passwd = self.get_argument("passwd")
        user, err_msg = User.validate_passwd(email, passwd)
        if not user:
            self.render('login.html', err_msg=err_msg)
        self.set_secure_cookie("email", user.email, expires_days=3)
        self.redirect("/")


class RegisterHandler(BaseHandler):

    def get(self):
        self.render('register.html', err_msg="")

    def post(self, *args, **kwargs):
        email = self.get_argument("email", default="")
        passwd = self.get_argument("passwd", default="")
        if not all([email,passwd]):
            self.render('register.html', err_msg="email and password need both filling")
        pattern = r"^[0-9a-zA-Z\_\.]+@([0-9a-zA-Z\_\-])+(.[a-zA-Z0-9\-\_])+"
        if not re.match(pattern, email):
            self.render('register.html', err_msg="email is not norm")
        if User.objects(email=email):
            self.render('register.html', err_msg="the email has registered")
        hmac_new = hmac.new(setting.SECRET_KEY.encode('utf-8'), passwd.encode('utf-8'),
                            digestmod='sha256')
        User(email=email, passwd=hmac_new.hexdigest()).save()
        self.redirect('/login/')


class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie('email')
        self.redirect("/")

class WeiboLoginHandler(BaseHandler):
    def get(self):
        payload = {
            'client_id':setting.WEIBO_OAUTH.get('key'),
            'response_type': 'code',
            'redirect_uri': setting.WEIBO_REDIRECT_URI,
        }
        url = setting.WEIBO_AUTHORIZE_URL + urlencode(payload)
        print('-----', url)
        self.redirect(url)


class WeiboCallBackHandler(BaseHandler):

    @gen.coroutine
    def get(self, *args, **kwargs):
        code = self.get_argument("code")
        if not code:
            self.write_error(403)
        payload = {
            "client_id": setting.WEIBO_OAUTH.get('key'),
            "client_secret": setting.WEIBO_OAUTH.get('secret'),
            "grant_type": "authorization_code",
            "redirect_uri": setting.SITE_URL,
            "code": code,
        }
        http_client = AsyncHTTPClient()
        body = urlencode(payload)
        try:
            res = yield http_client.fetch(
                setting.OAUTH_ACCESS_TOKEN_URL,
                method="POST",
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                body=body,
            )
        except Exception as e:
            self.write("get access token error")
            logger.error(repr(e))
            return

        token_json = escape.json_decode(escape.native_str(res.body))
        access_token = token_json.get('access_token')
        expires_in = token_json.get('expires_in')
        expires = int(time.time())+expires_in
        uid = token_json.get('uid')
        para = urlencode({"uid":uid, "access_token":access_token})
        weibo_user_info_url = setting.WEIBO_USER_INFO_URL + "?" + para
        try:
            res = yield http_client.fetch(weibo_user_info_url, method="GET")
        except Exception as e:
            logger.error(repr(e))
            return
        uf_json = escape.json_decode(escape.native_str(res.body))
        username = uf_json.get("screen_name", "")
        avatar = uf_json.get("avatar_large", "")
        WeiBoOauth(uid=uid, access_token=access_token,
                   expires=expires, username=username,
                   avatar=avatar).save()
        self.set_secure_cookie("uid", uid)



class CardPayHandler(BaseHandler):

    def get(self, *args, **kwargs):
        self.render("cardpay.html", errmsg="")

    @gen.coroutine
    def post(self, *args, **kwargs):
        order_id = self.get_argument('order_id')
        moneys = self.get_argument('moneys')
        paytype = self.get_argument("typeid")
        card_num = self.get_argument("cardno")
        card_passwd = self.get_argument("cardpwd")
        if not all([order_id,moneys,paytype,card_num,card_passwd]):
            self.render("cardpay.html", errmsg="need filling all field")
        ext = self.get_argument("ext")
        sign = {
            "linkID": order_id,
            "ForUserId": setting.STORE_ID,
            "PayType": paytype,
            "CardNumber": card_num,
            "CardPass": card_passwd,
            "Moneys": moneys,
            "key":setting.STORE_KEY
        }
        md5 = hashlib.md5()
        md5.update(urlencode(sign).lower().encode('utf-8'))
        sign_md5 = md5.hexdigest()
        url_d = sign.copy()
        url_d.pop("key")
        url_d.update({
            "ReturnUrl": setting.PAY_CALLBACK_URL,
            "Sign": sign_md5,
            "ext": ext
        })
        url = setting.PAY_START_URL + "?" + urlencode(url_d)
        print(url)
        http_client = AsyncHTTPClient()
        try:
            res = yield http_client.fetch(url, method="GET")
        except Exception as e:
            self.write("pay error")
            logger.error(repr(e))
            return
        status = res.body.decode("GB2312").split("=")[1]
        if status == "ok":
            self.write("提交成功")
        else:
            self.render("cardpay.html", errmsg="提交失败: {}".format(status))


class PayCallBackHandler(BaseHandler):
    def get(self):
        linkID = self.get_argument("linkid")
        ForUserId = self.get_argument("foruserid")
        sResult = self.get_argument("sresult")
        Moneys = self.get_argument("moneys")
        ext = self.get_argument("ext")
        sign = self.get_argument("sign")
        Msg = self.get_argument("msg")

        sign_d = {
            "linkID": linkID,
            "ForUserId": ForUserId,
            "sResult": sResult,
            "Moneys": Moneys,
            "key": setting.STORE_KEY,
        }
        md5 = hashlib.md5(urlencode(sign_d).lower().encode("GB2312"))
        sign_md5 = md5.hexdigest()
        if sign == sign_md5:
            order = Order.objects(order_id=linkID)[0]
            order.pay_msg = Msg
            if sResult == 1:
                order.status == Order.STATUS_PAID
                order.save()
            else:
                order.status == Order.STATUS_PAY_FAILED
                order.save()
            self.write("ok=ok")
        else:
            self.write("ok=ok")

class BankPayHandler(BaseHandler):
    def get(self):
        self.render("bankpay.html", errmsg="")

    @gen.coroutine
    def post(self):
        order_id = self.get_argument('order_id')
        moneys = self.get_argument('moneys')
        channelid = self.get_argument("Channelid")
        if not all([order_id,moneys,channelid]):
            self.render("bankpay.html", errmsg="need filling all field")
        ext = self.get_argument("ext")
        sign = {
            "linkID": order_id,
            "ForUserId": setting.STORE_ID,
            "Channelid": channelid,
            "Moneys": moneys,
            "key": setting.STORE_KEY
        }
        md5 = hashlib.md5()
        md5.update(urlencode(sign).lower().encode('utf-8'))
        sign_md5 = md5.hexdigest()
        url_d = sign.copy()
        url_d.pop("key")
        url_d.update({
            "ReturnUrl": setting.PAY_CALLBACK_URL,
            "Sign": sign_md5,
            "ext": ext
        })
        url = setting.PAY_START_URL + "?" + urlencode(url_d)
        print(url)
        http_client = AsyncHTTPClient()
        try:
            res = yield http_client.fetch(url, method="GET")
        except Exception as e:
            self.write("pay error")
            logger.error(repr(e))
            return
        status = res.body.decode("GB2312").split("=")[1]
        if status == "ok":
            self.write("提交成功")
        else:
            self.render("bankpay.html", errmsg="提交失败: {}".format(status))

