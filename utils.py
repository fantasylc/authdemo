from models import GlobalId


def gen_pay_order_id():
    return GlobalId.gen_id("pay_id")

