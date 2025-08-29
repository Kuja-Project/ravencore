Raven Core integration/staging tree

Ravencore (RVCR) – is a fork of Ravencoin

Raven Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Ravencore (RVCR) – is a fork of Ravencoin

Development Process
-------------------

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/RavenProject/Ravencoin/tags) are created
regularly to indicate new official, stable release versions of Raven Core.

Active development is done in the `develop` branch. 

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

Developer IRC is inactive please join us on discord in #development. https://discord.gg/fndp4NBGct

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

Testnet is up and running and available to use during development.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled in configure) with: `make check`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python, that are run automatically on the build server.
These tests can be run (if the [test dependencies](/test) are installed) with: `test/functional/test_runner.py`


### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.


Ravencore implements a blockchain optimized for transferring assets — such as collectibles, access tokens, in-game items, utility tokens, and other digital or real-world representations of value.

Like Ravencoin, Ravencore is based on a fork of Bitcoin, inheriting its tested and secure codebase while introducing changes tailored for asset management. These changes include:

An independent genesis block

A distinct coin ticker (RVCR)

Asset layer support for token creation and management

Mining and issuance rules without premine or developer allocation

Ravencore is free, open source, and launched transparently. It prioritizes user control, privacy, and censorship resistance, with optional features that expand usability without compromising the decentralized nature of the system.

A blockchain is, at its core, a ledger of ownership. The first and most successful use case was Bitcoin itself — transferring and securing monetary value. Ravencore extends this by focusing on asset transfer, enabling anyone to tokenize ownership and move it securely across a global, borderless network.

The demand for tokenized assets has been proven by Ethereum’s ERC-20 tokens, but neither Bitcoin nor Ethereum were purpose-built for efficient asset transfer. Ravencore addresses this by focusing solely on one function: the creation and transfer of assets from one party to another.

In an increasingly global economy, asset ownership must be secure, transferable, and resistant to censorship. Ravencore provides this foundation, ensuring that ownership records and transfers can operate independently of any single jurisdiction.

