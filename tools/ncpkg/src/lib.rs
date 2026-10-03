// SPDX-License-Identifier: Apache-2.0
//! The cryptography `ncpkg` signs and verifies with, as a library: keys
//! (`ncpkg keygen` files and the roots' `ncplu-sign` directories), every
//! accepted algorithm and hybrid, and the host's verifier. `tools/ncfs`
//! seals `ncinitramdisk` images with it, so there is one implementation of
//! all of it.

pub mod crypto;
