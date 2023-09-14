# -*- coding: utf-8 -*-
#
# Copyright 2019 Sergey Bronnikov

import os
import sys

from hypothesis.strategies import composite, one_of, characters, \
    text, permutations, builds, lists, sampled_from, just
from hypothesis.errors import InvalidArgument

text_type = type(u"")
PY3 = (sys.version_info[0] == 3)
defines_strategy = lambda x: x

@composite
def _filename(draw, result_type=None):
    """Generate a path value of type result_type.

    result_type can either be bytes or text_type

    """
    # Various ASCII chars have a special meaning for the operating system,
    # so make them more common
    ascii_char = characters(min_codepoint=0x01, max_codepoint=0x7f)
    if os.name == 'nt':
        # Windows paths can contain all surrogates and even surrogate pairs
        # if two paths are concatenated. This makes it more likely for them to
        # be generated.
        surrogate = characters(
            min_codepoint=0xD800, max_codepoint=0xDFFF)
        uni_char = characters(min_codepoint=0x1)
        text_strategy = text(
            alphabet=one_of(uni_char, surrogate, ascii_char))

        def text_to_bytes(path):
            fs_enc = sys.getfilesystemencoding()
            try:
                return path.encode(fs_enc, 'surrogatepass')
            except UnicodeEncodeError:
                return path.encode(fs_enc, 'replace')

        bytes_strategy = text_strategy.map(text_to_bytes)
    else:
        latin_char = characters(min_codepoint=0x01, max_codepoint=0xff)
        bytes_strategy = text(alphabet=one_of(latin_char, ascii_char)).map(
            lambda t: t.encode('latin-1'))

        unix_path_text = bytes_strategy.map(
            lambda b: b.decode(
                sys.getfilesystemencoding(),
                'surrogateescape' if PY3 else 'ignore'))

        # Two surrogates generated through surrogateescape can generate
        # a valid utf-8 sequence when encoded and result in a different
        # code point when decoded again. Can happen when two paths get
        # concatenated. Shuffling makes it possible to generate such a case.
        text_strategy = permutations(draw(unix_path_text)).map(u"".join)

    if result_type is None:
        return draw(one_of(bytes_strategy, text_strategy))
    elif result_type is bytes:
        return draw(bytes_strategy)
    else:
        return draw(text_strategy)

@composite
def _path_root(draw, result_type):
    """Generates a root component for a path."""

    # Based on https://en.wikipedia.org/wiki/Path_(computing)

    def tp(s=''):
        return _str_to_path(s, result_type)

    if os.name != 'nt':
        return tp(os.sep)

    sep = sampled_from([os.sep, os.altsep or os.sep]).map(tp)
    name = _filename(result_type)
    char = characters(min_codepoint=ord("A"), max_codepoint=ord("z")).map(
        lambda c: tp(str(c)))

    relative = sep
    # [drive_letter]:\
    drive = builds(lambda *x: tp().join(x), char, just(tp(':')), sep)
    # \\?\[drive_spec]:\
    extended = builds(
        lambda *x: tp().join(x), sep, sep, just(tp('?')), sep, drive)

    network = one_of([
        # \\[server]\[sharename]\
        builds(lambda *x: tp().join(x), sep, sep, name, sep, name, sep),
        # \\?\[server]\[sharename]\
        builds(lambda *x: tp().join(x),
               sep, sep, just(tp('?')), sep, name, sep, name, sep),
        # \\?\UNC\[server]\[sharename]\
        builds(lambda *x: tp().join(x),
               sep, sep, just(tp('?')), sep, just(tp('UNC')), sep, name, sep,
               name, sep),
        # \\.\[physical_device]\
        builds(lambda *x: tp().join(x),
               sep, sep, just(tp('.')), sep, name, sep),
    ])

    final = one_of(relative, drive, extended, network)

    return draw(final)


@defines_strategy
@composite
def fspaths(draw, allow_pathlike=None):
    """A strategy which generates filesystem path values.

    The generated values include everything which the builtin
    :func:`python:open` function accepts i.e. which won't lead to
    :exc:`ValueError` or :exc:`TypeError` being raised.

    Note that the range of the returned values depends on the operating
    system, the Python version, and the filesystem encoding as returned by
    :func:`sys.getfilesystemencoding`.

    :param allow_pathlike:
        If :obj:`python:None` makes the strategy include objects implementing
        the :class:`python:os.PathLike` interface when Python >= 3.6 is used.
        If :obj:`python:False` no pathlike objects will be generated. If
        :obj:`python:True` pathlike will be generated (Python >= 3.6 required)

    :type allow_pathlike: :obj:`python:bool` or :obj:`python:None`

    .. versionadded:: 3.15

    """
    has_pathlike = hasattr(os, 'PathLike')

    if allow_pathlike is None:
        allow_pathlike = has_pathlike
    if allow_pathlike and not has_pathlike:
        raise InvalidArgument(
            'allow_pathlike: os.PathLike not supported, use None instead '
            'to enable it only when available')

    result_type = draw(sampled_from([bytes, text_type]))

    def tp(s=''):
        return _str_to_path(s, result_type)

    special_component = sampled_from([tp(os.curdir), tp(os.pardir)])
    normal_component = _filename(result_type)
    path_component = one_of(normal_component, special_component)
    extension = normal_component.map(lambda f: tp(os.extsep) + f)
    root = _path_root(result_type)

    sep = sampled_from([os.sep, os.altsep or os.sep]).map(tp)
    path_part = builds(lambda s, l: s.join(l), sep, lists(path_component))
    main_strategy = builds(lambda *x: tp().join(x),
                           optional(root), path_part, optional(extension))

    if allow_pathlike and hasattr(os, 'fspath'):
        pathlike_strategy = main_strategy.map(lambda p: _PathLike(p))
        main_strategy = one_of(main_strategy, pathlike_strategy)

    return draw(main_strategy)
