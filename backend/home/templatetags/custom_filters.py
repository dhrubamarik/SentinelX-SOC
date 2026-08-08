from django import template

register = template.Library()

@register.filter
def replace(value, args):
    """
    Replaces a substring in the value.
    Usage: {{ value|replace:"old,new" }}
    """
    try:
        old, new = args.split(',')
        return value.replace(old, new)
    except (ValueError, AttributeError):
        return value


@register.filter
def get_item(dictionary, key):
    """
    Gets an item from a dictionary.
    Usage: {{ dict|get_item:"key" }}
    """
    return dictionary.get(key)


@register.filter
def contains(list_value, search_term):
    """
    Checks if a list contains a search term.
    Usage: {{ list|contains:"term" }}
    """
    return any(search_term in str(item) for item in list_value)