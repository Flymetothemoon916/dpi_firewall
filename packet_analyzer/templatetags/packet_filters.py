from django import template
import json
import pprint

register = template.Library()

@register.filter
def pprint_json(value):
    """美化打印JSON数据"""
    try:
        if isinstance(value, str):
            parsed = json.loads(value)
        else:
            parsed = value
        return json.dumps(parsed, indent=2, ensure_ascii=False)
    except:
        return str(value)