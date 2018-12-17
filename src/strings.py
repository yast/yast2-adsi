import six

def strcmp(first, second):
    if six.PY3:
        if isinstance(first, six.string_types):
            first = six.binary_type(first, 'utf8')
        if isinstance(second, six.string_types):
            second = six.binary_type(second, 'utf8')
    return first == second

def strcasecmp(first, second):
    if six.PY3:
        if isinstance(first, six.string_types):
            first = six.binary_type(first, 'utf8')
        if isinstance(second, six.string_types):
            second = six.binary_type(second, 'utf8')
    return first.lower() == second.lower()
