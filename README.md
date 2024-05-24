easytls
=======
[![Latest release][latest-release-img]][latest-release-url]
[![Build status][build-status-img]][build-status-url]
[![Go Report Card][report-img]][report-url]
[![Documentation][doc-img]][doc-url]

[latest-release-img]: https://img.shields.io/github/release/go-pogo/easytls.svg?label=latest

[latest-release-url]: https://github.com/go-pogo/easytls/releases

[build-status-img]: https://github.com/go-pogo/easytls/actions/workflows/test.yml/badge.svg

[build-status-url]: https://github.com/go-pogo/easytls/actions/workflows/test.yml

[report-img]: https://goreportcard.com/badge/github.com/go-pogo/easytls

[report-url]: https://goreportcard.com/report/github.com/go-pogo/easytls

[doc-img]: https://godoc.org/github.com/go-pogo/easytls?status.svg

[doc-url]: https://pkg.go.dev/github.com/go-pogo/easytls


Package `easytls` makes working with TLS for either servers or clients easy.
It contains several sane and safe defaults for implementing TLS and using certificates, as well as _loader_ interfaces
to accelerate the process of loading certificates from files or raw byte data.

<hr>

```sh
go get github.com/go-pogo/easytls
```

```go
import "github.com/go-pogo/easytls"
```

## Documentation

Additional detailed documentation is available at [pkg.go.dev][doc-url]

## Created with

<a href="https://www.jetbrains.com/?from=go-pogo" target="_blank"><img src="https://resources.jetbrains.com/storage/products/company/brand/logos/GoLand_icon.png" width="35" /></a>

## License

Copyright © 2022-2024 [Roel Schut](https://roelschut.nl). All rights reeasytlsed.

This project is governed by a BSD-style license that can be found in the [LICENSE](LICENSE) file.
