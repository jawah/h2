# -*- coding: utf-8 -*-
"""
test_basic_logic
~~~~~~~~~~~~~~~~

Test the basic logic of the h2 state machines.
"""
import h2.connection


class TestBasicConnection(object):
    """
    Basic connection tests.
    """
    example_request_headers = [
        (':authority', 'example.com'),
        (':path', '/'),
        (':scheme', 'https'),
        (':method', 'GET'),
    ]

    def test_begin_connection(self):
        c = h2.connection.H2Connection()
        frames = c.send_headers_on_stream(1, self.example_request_headers)
        assert len(frames) == 1
