"""
This type stub file was generated by pyright.
"""

import sys

"""
Functions to convert unicode IRIs into ASCII byte string URIs and back. Exports
the following items:

 - iri_to_uri()
 - uri_to_iri()
"""
if sys.version_info < (3, ):
    ...
else:
    ...
def iri_to_uri(value, normalize=...): # -> bytes:
    """
    Encodes a unicode IRI into an ASCII byte string URI

    :param value:
        A unicode string of an IRI

    :param normalize:
        A bool that controls URI normalization

    :return:
        A byte string of the ASCII-encoded URI
    """
    ...

def uri_to_iri(value): # -> str:
    """
    Converts an ASCII URI byte string into a unicode IRI

    :param value:
        An ASCII-encoded byte string of the URI

    :return:
        A unicode string of the IRI
    """
    ...
