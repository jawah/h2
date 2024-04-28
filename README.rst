==========================
jh2: HTTP/2 Protocol Stack
==========================

This repository is a fork of the well known hyper/h2 package. We want to provide a cleaner and faster HTTP/2
state machine while keeping a pure Python implementation. We decided to embed the leaf dependencies as we want
a neater dependency tree and along with that a easier maintenance burden. We believe it was a mistake to ship
three packages (h2, hpack, and hyperframe).

Analysis shown that h2 spend a lot of time doing hpack encode and decode operations, this is why we decided to offer
a complementary optimized build. The pure Python version will still be available.

This repository contains a pure-Python implementation of a HTTP/2 protocol
stack. It's written from the ground up to be embeddable in whatever program you
choose to use, ensuring that you can speak HTTP/2 regardless of your
programming paradigm.

You use it like this:

.. code-block:: python

    import jh2.connection
    import jh2.config

    config = jh2.config.H2Configuration()
    conn = jh2.connection.H2Connection(config=config)
    conn.send_headers(stream_id=stream_id, headers=headers)
    conn.send_data(stream_id, data)
    socket.sendall(conn.data_to_send())
    events = conn.receive_data(socket_data)

This repository does not provide a parsing layer, a network layer, or any rules
about concurrency. Instead, it's a purely in-memory solution, defined in terms
of data actions and HTTP/2 frames. This is one building block of a full Python
HTTP implementation.

To install it, just run:

.. code-block:: console

    $ python -m pip install jh2

Documentation
=============

Documentation is available at https://h2.readthedocs.io .

Contributing
============

``jh2`` welcomes contributions from anyone! Unlike many other projects we
are happy to accept cosmetic contributions and small contributions, in addition
to large feature requests and changes.

Before you contribute (either by opening an issue or filing a pull request),
please `read the contribution guidelines`_.

.. _read the contribution guidelines: http://python-hyper.org/en/latest/contributing.html

License
=======

``jh2`` is made available under the MIT License. For more details, see the
``LICENSE`` file in the repository.

Authors
=======

``h2`` was authored by Cory Benfield and is maintained by the Jawah OSS organization under the ``jh2`` name.
