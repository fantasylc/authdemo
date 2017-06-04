from mongoengine import (
    connect,
    Document,
    StringField,
    IntField,
    DateTimeField,
    ObjectIdField,
    DecimalField
)
import datetime
import hmac
import setting
connect("authdemo",)


class User(Document):
    username = StringField(max_length=30)
    email = StringField(max_length=100, unique=True)
    passwd = StringField(max_length=64, required=True)
    created_at = DateTimeField(default=datetime.datetime.now)
    updated_at = DateTimeField(default=datetime.datetime.now)

    @classmethod
    def validate_passwd(cls, email, passwd):
        users = cls.objects(email=email)
        if not users:
            return None, "user not found"
        user = users[0]
        hmac_new = hmac.new(setting.SECRET_KEY.encode('utf-8'), passwd.encode('utf-8'),
                            digestmod='sha256')
        if user.passwd == hmac_new.hexdigest():
            return user, ''
        else:
            return None, 'passwd is error'

    def __repr__(self):
        return self.email


class WeiBoOauth(Document):
    user_id = ObjectIdField()           #绑定用户
    uid = StringField(max_length=30, default='', required=True)
    access_token = StringField(max_length=200, default='', required=True)
    expires = IntField()
    username = StringField(max_length=100, default="")
    avatar = StringField(max_length=200, default="")
    created_at = DateTimeField(default=datetime.datetime.now)
    updated_at = DateTimeField(default=datetime.datetime.now)



class Order(Document):
    STATUS_CREATED = 0
    STATUS_PAID = 1
    STATUS_FINISH = 3
    STATUS_REFUNDED = 4
    STATUS_USER_CANCELLED = 5
    STATUS_PAY_FAILED = 6
    STATUS_ADMIN_CANCELLED = 7

    STATUS = (
        (STATUS_CREATED, "创建"),
        (STATUS_PAID, "支付完成"),
        (STATUS_REFUNDED, "退单中"),
        (STATUS_USER_CANCELLED,"取消订单"),
        (STATUS_PAY_FAILED,"支付失败"),
        (STATUS_ADMIN_CANCELLED, "系统取消"),
        (STATUS_FINISH, "订单结束")
    )

    order_id = IntField()
    user_id = IntField()
    money = DecimalField()
    status = IntField(choices=STATUS)
    pay_msg = StringField(max_length=255)