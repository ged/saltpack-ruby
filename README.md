# Saltpack

home
: http://bitbucket.org/ged/saltpack-ruby

github
: https://github.com/ged/saltpack-ruby

docs
: http://deveiate.org/code/saltpack


## Description

A Ruby implementation of Saltpack, a modern crypto messaging format based on Dan Bernstein's [NaCl][].

See also: <https://saltpack.org/>


## Prerequisites

* Ruby


## Installation

    $ gem install saltpack


## Contributing

You can check out the current development source with Mercurial via its
[project page][saltpack-ruby]. Or if you prefer Git, via 
[its Github mirror][github-mirror].

After checking out the source, run:

    $ rake newb

This task will install any missing dependencies, run the tests/specs,
and generate the API documentation.


## License

Large portions of this library are ported from the [saltpack-python][] library by
Jack O'Connor &lt;oconnor663+pypi@gmail.com&gt;, used under the terms of the MIT
License. No license statement is included in the source, but I'm assuming it's
something like:

> Copyright © 2018 Jack O'Connor
>
> Permission is hereby granted, free of charge, to any person obtaining
> a copy of this software and associated documentation files (the
> “Software”), to deal in the Software without restriction, including
> without limitation the rights to use, copy, modify, merge, publish,
> distribute, sublicense, and/or sell copies of the Software, and to
> permit persons to whom the Software is furnished to do so, subject to
> the following conditions:
>
> The above copyright notice and this permission notice shall be
> included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY
> KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
> WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
> NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
> LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
> OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
> WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

The port and the rest of the code is:

Copyright © 2018-2019, Michael Granger
All rights reserved.

And is also distributed under the terms of the MIT license.


[NaCl]: https://nacl.cr.yp.to/
[saltpack-ruby]: http://bitbucket.org/ged/saltpack-ruby
[github-mirror]: https://github.com/ged/saltpack-ruby
[saltpack-python]: https://github.com/keybase/saltpack-python
