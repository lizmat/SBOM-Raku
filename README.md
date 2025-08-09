[![Actions Status](https://github.com/lizmat/SBOM-Raku/actions/workflows/linux.yml/badge.svg)](https://github.com/lizmat/SBOM-Raku/actions) [![Actions Status](https://github.com/lizmat/SBOM-Raku/actions/workflows/macos.yml/badge.svg)](https://github.com/lizmat/SBOM-Raku/actions) [![Actions Status](https://github.com/lizmat/SBOM-Raku/actions/workflows/windows.yml/badge.svg)](https://github.com/lizmat/SBOM-Raku/actions)

NAME
====

SBOM::Raku - Raku specific SBOM functionality 

SYNOPSIS
========

```raku
use SBOM::Raku;

say source-sbom("META6.json").JSON;
# {
#   "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
#   "bomFormat": "CycloneDX",
#   "specVersion": "1.6",
#   "version": 1,
#   "metadata": {
#     "timestamp": "2025-07-22T18:39:29.458604+02:00",
# ...
```

DESCRIPTION
===========

The `SBOM::Raku` distribution provides logic for the creation and maintenance of SBOM (Software Bill Of Materials) files in the Raku Programming Language context.

SCRIPTS
=======

source-sbom
-----------

    $ source-sbom META6.json
    Created 1 source SBOM

The `source-sbom` script expects at least one "META6.json" file to be specified. It will try to create source SBOM files for each of the "META6.json" files specified in tyeir sibling directory `.META`. If this is a newly created file, an attempt will be made to add it to the repository in which it is residing.

modernize-meta
--------------

    $ modernize-meta META6.json
    Updated 1 META6.json file

The `modernize-meta` script expects at least one "META6.json" file to be specified. It will try to update the specified file(s) to match modern META specifications:

  * replace "depends" field with an array specification by a hash with extended specifications.

  * remove "build-dependencies" and "test-dependencies" and put any information in there into the "depends" hash

  * add "raku" field, take (and remove) "perl" field if there is any

  * remove "author" field: put any contents in the "authors" field array

  * remove empty array fields

  * add "support" field hash with at least a "bugtracker" field

  * move the "source-url" field to the "support" fueld hash

SELECTIVE IMPORTING
===================

```raku
use SBOM::Raku <component>;  # only import "component"
```

By default all utility functions are exported. But you can limit this to the functions you actually need by specifying the names in the `use` statement.

To prevent name collisions and/or import any subroutine with a more memorable name, one can use the "original-name:known-as" syntax. A semi-colon in a specified string indicates the name by which the subroutine is known in this distribution, followed by the name with which it will be known in the lexical context in which the `use` command is executed.

```raku
use String::Utils <component:comp>;  # import "component" as "comp"
say comp |%args;
```

Apart from the subroutines provided by the `SBOM::Raku` distribution, it also possible to import the following subroutines from other packages, but which are used internally by `SBOM::Raku`:

<table class="pod-table">
<thead><tr>
<th>Package</th> <th>importable subroutines</th>
</tr></thead>
<tbody>
<tr> <td>JSON::Fast</td> <td>from-json, to-json</td> </tr> <tr> <td>Identity::Utils</td> <td>auth, build, meta, dependencies-from-meta, distribution-name, ecosystem, is-pinned, issue-tracker-url, raku-land-url, short-name, source-distribution-url, ver</td> </tr> <tr> <td>String::Utils</td> <td>after, before, describe-Version</td> </tr>
</tbody>
</table>

SUBROUTINES
===========

authors
-------

```raku
dd authors(from-json "META6.json".IO.slurp);
# (SBOM::Contact.new(|Map.new((:name("Jane Doe")))),)
```

The `authors` subroutine returns a `List` with `SBOM::Contact` objects for the authors of the JSON hash from a META6.json file.

component
---------

```raku
say component("META6.json").JSON;
# {
#   "type": "library",
#   "mime-type": "text/plain",
# ...

my %meta-json = ...;
my $component = component(%meta-json);
```

The `component` subroutine returns a [SBOM::Component](https://raku.land/zef:lizmat/SBOM::CycloneDX#sbomcomponent) for the given arguments.

The arguments can be either an `IO::Path` object (or a string that can be coerced to an `IO::Path`) to a file that contains Raku module meta information (usually called `META6.json`). Or a hash with arguments (in the `META6.json` format) to build an `SBOM::Component` object with.

component-hash
--------------

```raku
my %args := component-hash("META6.json");
# ... perform tweaks
my $component = SBOM::Component.new(|%args);
```

The `component-hash` subroutine returns a hash in the format needed to create an `SBOM::Component` object with, from a `META6.json` file (or a hash of that representation).

It's main intended use is to be able to tweak the arguments prior to making an `SBOM::Component` object.

contact
-------

```raku
my $contact = contact("Jane Doe");
```

The `contact` subroutine creates a unique `SBOM::Contact` object for the given string, providing from a cache if necessary.

licenses
--------

```raku
dd licenses(from-json "META6.json".IO.slurp);
# (SBOM::License.new(|Map.new((:license(Map.new((:id("Artistic-2.0"))))))),)
```

The `licenses` subroutine returns a `List` with `SBOM::License` objects for the license(s) of the JSON hash from a META6.json file.

metadata
--------

```raku
say metadata("META6.json").JSON;
# {
#   "timestamp": "2025-07-22T18:52:04.686316+02:00",
#   "lifecycles": [
#     {
#       "phase": "build"
# ...

my %meta-json = ...;
my $metadata = metadata(%meta-json);
```

The `metadata` subroutine returns a [SBOM::Metadata](https://raku.land/zef:lizmat/SBOM::CycloneDX#sbommetadata) for the given arguments.

The arguments can be either an `IO::Path` object (or a string that can be coerced to an `IO::Path`) to a file that contains Raku module meta information (usually called `META6.json`). Or a hash with arguments (in the `META6.json` format) to build an `SBOM::Metadata` object with.

metadata-hash
-------------

```raku
my %args := metadata-hash("META6.json");
# ... perform tweaks
my $metadata = SBOM::Metadata.new(|%args);
```

The `metadata-hash` subroutine returns a hash in the format needed to create an `SBOM::Metadata` object with, from a `META6.json` file (or a hash of that representation).

It's main intended use is to be able to tweak the arguments prior to making an `SBOM::Metadata` object.

modernize-META6
---------------

```raku
modernize-META6("META6.json");  # modernize in place

modernize-META6("META6.json", "modernized.json");
```

Read the META information at the path by the first positional argument and produce a modernized version at the path specified by the optional second argument (defaults to the first argument).

Optionally takes these named arguments, each taking a `Callable` to be executed when certain events take place:

<table class="pod-table">
<thead><tr>
<th>name</th> <th>arguments</th>
</tr></thead>
<tbody>
<tr> <td>:changed</td> <td>IO::Path of changed file</td> </tr> <tr> <td>:error</td> <td>IO::Path of file with error, error message</td> </tr>
</tbody>
</table>

This subroutine may have limited production value, but it's the workhorse of the `modernize-meta` script, so it's included here for convenience. For more info on the changes, see the documentation of the script.

produce-source-sbom
-------------------

```raku
produce-source-sbom("META6.json");  # written to .META/SOURCE.cdx.json

produce-source-sbom("META6.json", ".META/SOURCE.cdx.json");

sub error($io, $error) { die "$io: $error }
produce-source-sbom("META6.json", :&error);
```

Read the META information at the path by the first positional argument and produce a `source-sbom` at the path specified by the optional second argument (defaults to ".META/SOURCE.cdx.json" in the same directory as the path of the first arguments).

If the file didn't exist before, it will be added to the repository if possible.

Optionally takes these named arguments, each taking a `Callable` to be executed when certain events take place:

<table class="pod-table">
<thead><tr>
<th>name</th> <th>arguments</th>
</tr></thead>
<tbody>
<tr> <td>:created</td> <td>IO::Path of created file</td> </tr> <tr> <td>:updated</td> <td>IO::Path of updated file</td> </tr> <tr> <td>:error</td> <td>IO::Path of file with error, error message</td> </tr>
</tbody>
</table>

This subroutine may have limited production value, but it's the workhorse of the `source-sbom` script, so it's included here for convenience.

Rakudo-component
----------------

```raku
my $comp = Rakudo-component;
```

Returns a `SBOM::Component` object representing the version of Rakudo is running.

source-sbom
-----------

```raku
say source-sbom("META6.json").JSON;
# {
#   "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
#   "bomFormat": "CycloneDX",
#   "specVersion": "1.6",
#   "version": 1,
#   "metadata": {
#     "timestamp": "2025-07-22T18:53:59.841267+02:00",
# ...

my %meta-json = ...;
my $sbom = source-sbom(%meta-json);
```

The `source-sbom` subroutine returns a [SBOM::CycloneDX](https://raku.land/zef:lizmat/SBOM::CycloneDX#sbomcyclonedx) for the given arguments.

The arguments can be either an `IO::Path` object (or a string that can be coerced to an `IO::Path`) to a file that contains Raku module meta information (usually called `META6.json`). Or a hash with arguments (in the `META6.json` format) to build an `SBOM::CycloneDX` object with.

source-sbom-hash
----------------

```raku
my %args := source-sbom-hash("META6.json");
# ... perform tweaks
my $sbom = SBOM::CycloneDX.new(|%args);
```

The `source-sbom-hash` subroutine returns a hash in the format needed to create an `SBOM::CycloneDX` object with, from a `META6.json` file (or a hash of that representation).

It's main intended use is to be able to tweak the arguments prior to making an `SBOM::CycloneDX` object.

tar-sbom
--------

```raku
my $sbom = tar-sbom("releases/SBOM-Raku-0.0.1.tar.gz");
```

The `tar-sbom` subroutine returns a [SBOM::CycloneDX](https://raku.land/zef:lizmat/SBOM::CycloneDX#sbomcyclonedx) for the given path, which is expected to indicate a tar-file.

tar-sbom-hash
-------------

```raku
my %args := tar-sbom-hash("releases/SBOM-Raku-0.0.1.tar.gz");
# ... perform tweaks
my $sbom = SBOM::CycloneDX.new(|%args);
```

The `tar-sbom-hash` subroutine returns a hash in the format needed to create an `SBOM::CycloneDX` object with, from a tar-file that contains a `META6.json` file (or a hash of that representation). Apart from just creating the hash, it will also add crypto hashes for the tar-file to the component in the metadata.

It's main intended use is to be able to tweak the arguments prior to making an `SBOM::CycloneDX` object.

VM-component
------------

```raku
my $comp = VM-component;
```

Returns a `SBOM::Component` object representing the value of `$*VM` that is currently set.

AUTHOR
======

Elizabeth Mattijsen <liz@raku.rocks>

Source can be located at: https://github.com/lizmat/SBOM-Raku . Comments and Pull Requests are welcome.

If you like this module, or what I’m doing more generally, committing to a [small sponsorship](https://github.com/sponsors/lizmat/) would mean a great deal to me!

COPYRIGHT AND LICENSE
=====================

Copyright 2025 Elizabeth Mattijsen

This library is free software; you can redistribute it and/or modify it under the Artistic License 2.0.

