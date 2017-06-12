from urllib.parse import urlencode
import logging
import tornado.web
from tornado import gen
from tornado.httpclient import AsyncHTTPClient
from tornado import escape
import setting
from models import User, WeiBoOauth, PayOrder
import hmac
import re
import hashlib
import time
import jwt
from utils import gen_pay_order_id, is_from_mobile

logger = logging.getLogger(__name__)

class BaseHandler(tornado.web.RequestHandler):

    def get_current_user(self):
        auth_token = self.get_secure_cookie("auth_token")
        if not auth_token:
            return None
        try:
            payload = jwt.decode(auth_token, setting.JWT_SECRET, algorithm='HS256')
        except jwt.ExpiredSignatureError:
            return None

        expire_time = payload['exp']
        now = int(time.time())
        if expire_time - now < setting.JWT_EXPIRE_TIME / 2:  # 如果时间过期，自动增加过期时间
            payload['exp'] = now + setting.JWT_EXPIRE_TIME
            self.set_secure_cookie("auth_token", jwt.encode(payload, setting.JWT_SECRET,algorithm='HS256'))

        email = payload.get("email")

        print("email: ", email)
        if not email:
            return None
        user = User.objects(email=email).first()
        if not user:
            return None
        return user


class IndexHandler(BaseHandler):
    def get(self):
        print("a:", self.xsrf_token)
        print(self.request.headers['User-Agent'])
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
        payload = {
            "email": email,
            "exp": int(time.time())+setting.JWT_EXPIRE_TIME
        }

        self.set_secure_cookie("auth_token", jwt.encode(payload, setting.JWT_SECRET, algorithm='HS256'))
        print("user: ", user)
        print(self.get_secure_cookie("email"))
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
        self.clear_cookie('auth_token')
        self.redirect("/")


class CardPayHandler(BaseHandler):

    def get(self, *args, **kwargs):
        self.render("cardpay.html", errmsg="")

    @gen.coroutine
    def post(self, *args, **kwargs):
        moneys = self.get_argument('moneys', "")
        paytype = self.get_argument("typeid", "")
        card_num = self.get_argument("cardno", "")
        card_passwd = self.get_argument("cardpwd", "")
        if not all([moneys, paytype, card_num, card_passwd]):
            self.render("cardpay.html", errmsg="字段不能为空")
        ext = self.get_argument("ext", "")
        order_id = gen_pay_order_id()
        sign_s = "linkid={}&foruserid={}&paytype={}&cardnumber={}&cardpass={}&moneys={}&key={}".format(
            order_id,setting.STORE_ID,paytype,card_num,card_passwd,moneys,setting.STORE_KEY
        )
        md5 = hashlib.md5()
        md5.update(sign_s.lower().encode('utf-8'))
        sign_md5 = md5.hexdigest()
        gen_url = "linkid={}&foruserid={}&PayType={}&CardNumber={}&moneys={}&returnurl={}&sign={}".format(order_id,
                 setting.STORE_ID, paytype,card_num,card_passwd, moneys, setting.PAY_CALLBACK_URL, sign_md5)
        if ext:
            gen_url = gen_url + "&ext={}".format(ext)
        url = setting.CARD_PAY_URL + "?" + gen_url
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
            if self.current_user:
                payorder = PayOrder(user_id=str(self.current_user.id), pay_order_id=order_id, pay_type=PayOrder.TYPE_CARD, status=PayOrder.STATUS_CREATE).save()
            else:
                payorder = PayOrder(pay_order_id=order_id, pay_type=PayOrder.TYPE_CARD, status=PayOrder.STATUS_CREATE).save()
            data = {"status_code": setting.STATUS_SUC, "msg": "success",
                    "data": {"pay_order_id": payorder.pay_order_id}}
            self.finish(data)
        else:
            data = {"status_code": setting.STATUS_FAIL, "msg": status,
                    "data": {}}
            self.finish(data)



class BankPayHandler(BaseHandler):
    def get(self):
        self.render("bankpay.html", errmsg="")

    @gen.coroutine
    def post(self):
        moneys = self.get_argument('moneys')
        channelid = self.get_argument("channelid")
        if not all([moneys,channelid]):
                self.render("bankpay.html", errmsg="need filling all field")
        print("lala")
        ext = self.get_argument("ext", "")
        order_id = gen_pay_order_id()
        sign_s = "linkid={}&foruserid={}&channelid={}&moneys={}&key={}".format(
            order_id, setting.STORE_ID, channelid, moneys, setting.STORE_KEY)
        md5 = hashlib.md5()
        md5.update(sign_s.lower().encode('GB2312'))
        sign_md5 = md5.hexdigest()

        gen_url = "linkid={}&foruserid={}&channelid={}&moneys={}&returnurl={}&sign={}".format(order_id, setting.STORE_ID,
                                                                                              channelid,moneys, setting.PAY_CALLBACK_URL,
                                                                                              sign_md5)
        if ext:
            gen_url = gen_url + "&ext={}".format(ext)
        url = setting.BANK_PAY_URL + "?" + gen_url
        if self.current_user:
            payorder = PayOrder(user_id=str(self.current_user.id), pay_order_id=order_id, pay_type=PayOrder.TYPE_BANK, status=PayOrder.STATUS_CREATE).save()
        else:
            payorder = PayOrder(pay_order_id=order_id, pay_type=PayOrder.TYPE_BANK, status=PayOrder.STATUS_CREATE).save()

        print(url)
        self.redirect(url)

class CardMobilePayHandler(BaseHandler):

    def get(self, *args, **kwargs):
        self.set_cookie("_xsrf", self.xsrf_token)

    @gen.coroutine
    def post(self, *args, **kwargs):
        moneys = self.get_argument('moneys', "")
        paytype = self.get_argument("typeid", "")
        card_num = self.get_argument("cardno", "")
        card_passwd = self.get_argument("cardpwd", "")
        if not all([moneys, paytype, card_num, card_passwd]):
            data = {"status_code": setting.STATUS_FAIL, "msg": "字段不能为空", "data": {}}
            self.finish(data)
        ext = self.get_argument("ext", "")
        order_id = gen_pay_order_id()
        sign_s = "linkid={}&foruserid={}&paytype={}&cardnumber={}&cardpass={}&moneys={}&key={}".format(
            order_id,setting.STORE_ID,paytype,card_num,card_passwd,moneys,setting.STORE_KEY
        )
        md5 = hashlib.md5()
        md5.update(sign_s.lower().encode('utf-8'))
        sign_md5 = md5.hexdigest()
        gen_url = "linkid={}&foruserid={}&PayType={}&CardNumber={}&moneys={}&returnurl={}&sign={}".format(order_id,
                 setting.STORE_ID, paytype,card_num,card_passwd, moneys, setting.PAY_CALLBACK_URL, sign_md5)
        if ext:
            gen_url = gen_url + "&ext={}".format(ext)
        url = setting.CARD_PAY_URL + "?" + gen_url
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
            if self.current_user:
                payorder = PayOrder(user_id=str(self.current_user.id), pay_order_id=order_id, pay_type=PayOrder.TYPE_CARD, status=PayOrder.STATUS_CREATE).save()
            else:
                payorder = PayOrder(pay_order_id=order_id, pay_type=PayOrder.TYPE_CARD, status=PayOrder.STATUS_CREATE).save()
            data = {"status_code": setting.STATUS_SUC, "msg": "success",
                    "data": {"pay_order_id": payorder.pay_order_id}}
            self.finish(data)
        else:
            data = {"status_code": setting.STATUS_FAIL, "msg": status,
                    "data": {}}
            self.finish(data)


class BankMobilePayHandler(BaseHandler):
    def get(self, *args, **kwargs):
        self.set_cookie("_xsrf", self.xsrf_token)

    @gen.coroutine
    def post(self):
        moneys = self.get_argument('moneys')
        channelid = self.get_argument("channelid")
        if not all([moneys,channelid]):
            data = {"status_code": setting.STATUS_FAIL, "msg": "字段不能为空", "data": {}}
            self.finish(data)
        print("lala")
        ext = self.get_argument("ext", "")
        order_id = gen_pay_order_id()
        sign_s = "linkid={}&foruserid={}&channelid={}&moneys={}&key={}".format(
            order_id, setting.STORE_ID, channelid, moneys, setting.STORE_KEY)
        md5 = hashlib.md5()
        md5.update(sign_s.lower().encode('GB2312'))
        sign_md5 = md5.hexdigest()

        gen_url = "linkid={}&foruserid={}&channelid={}&moneys={}&returnurl={}&sign={}".format(order_id, setting.STORE_ID,
                                                                                              channelid,moneys, setting.PAY_CALLBACK_URL,
                                                                                              sign_md5)
        if ext:
            gen_url = gen_url + "&ext={}".format(ext)
        url = setting.BANK_PAY_URL + "?" + gen_url
        if self.current_user:
            payorder = PayOrder(user_id=str(self.current_user.id), pay_order_id=order_id, pay_type=PayOrder.TYPE_BANK, status=PayOrder.STATUS_CREATE).save()
        else:
            payorder = PayOrder(pay_order_id=order_id, pay_type=PayOrder.TYPE_BANK, status=PayOrder.STATUS_CREATE).save()

        data = {"status_code": setting.STATUS_SUC, "msg": "success", "data": {"pay_url": url, "pay_order_id": payorder.pay_order_id}}
        self.finish(data)

class PayCallBackHandler(BaseHandler):
    def get(self):
        linkID = self.get_argument("linkID", "")
        ForUserId = self.get_argument("ForUserId", "")
        sResult = self.get_argument("sResult", "")
        Moneys = self.get_argument("Moneys", "")
        ext = self.get_argument("ext", "")
        sign = self.get_argument("sign", "")
        Msg = self.get_argument("msg", default="")
        sign_s = "linkid={}&foruserId={}&sresult={}&moneys={}&key={}".format(
            linkID, ForUserId, sResult, Moneys, setting.STORE_KEY)
        md5 = hashlib.md5(sign_s.lower().encode("GB2312"))
        sign_md5 = md5.hexdigest()
        if sign == sign_md5:
            pay_order = PayOrder.objects(pay_order_id=int(linkID)).first()
            if not pay_order:
                self.finish("no")
            if pay_order and (pay_order.status in [PayOrder.STATUS_FAIL, PayOrder.STATUS_SUC]):
                self.finish("ok")
            if int(sResult) == 1:
                pay_order.status = PayOrder.STATUS_SUC
                pay_order.money = float(Moneys)
                pay_order.msg = Msg
                pay_order.save()
                logger.info("order: {} pay success".format(linkID))
                self.finish("ok")
            else:
                pay_order.status = PayOrder.STATUS_FAIL
                pay_order.msg = Msg
                pay_order.save()
                logger.info("order: {} pay fail".format(linkID))
                self.finish("no")
        else:
            self.finish("Sign_Erro{}".format(sign))


class PayResultHandler(BaseHandler):
    def get(self):
        if not self.current_user:
            self.finish({"status_code": 403, "msg": "you have not login", "data":{} })
        order_id = self.get_argument("pay_order_id")
        print(self.current_user.id)
        pay_order = PayOrder.objects(pay_order_id=int(order_id), user_id=str(self.current_user.id)).first()
        if not pay_order:
            data = {"status_code": setting.STATUS_404, "msg": "order cannot found", "data": {}}
            self.finish(data)
            return
        if pay_order.status == PayOrder.STATUS_CREATE:
            data = {"status_code": setting.STATUS_FAIL, "msg": "order has not paid over", "data": {}}
            self.finish(data)
            return
        else:
            if pay_order.status == PayOrder.STATUS_SUC:
                data = {"status_code": setting.STATUS_SUC, "msg": pay_order.msg, "data": {"result": "success"}}
            else:
                data = {"status_code": setting.STATUS_SUC, "msg": pay_order.msg, "data": {"result": "fail"}}
            self.finish(data)


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
        self.redirect("/")

