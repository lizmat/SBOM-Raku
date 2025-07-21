use JSON::Fast:ver<0.19+>:auth<cpan:TIMOTIMO>;
use SBOM::CycloneDX:ver<0.0.7+>:auth<zef:lizmat>;

use Identity::Utils:ver<0.0.21+>:auth<zef:lizmat> <
  auth build ecosystem is-pinned rakuland short-name ver
>;
use SBOM::enums:ver<0.0.7+>:auth<zef:lizmat> <
  Acknowledgement ComponentType LicenseId ReferenceSource Scope 
>;
use PURL:ver<0.0.5+>:auth<zef:lizmat>;

#- component -------------------------------------------------------------------
my proto sub component(|) {*}
my multi sub component(IO() $io, *%_) {
    component from-json($io.slurp, :immutable), |%_
}
my multi sub component(
   %json,
  :$type  = "library",
  :$scope = "required",
  :$raw-error,
  *%_
) {
    %_<type>  := ComponentType($type);  # throws if invalid
    %_<scope> := Scope($scope);         # throws if invalid

    %_<name>    := %json<name>    // die "Name must be specified";
    %_<version> := %json<version> // die "Version must be specified";

    my @authors is List = (%json<authors> || %json<author>).map: -> $name {
        SBOM::Contact.new(:$name)
    }
    die "Must have one or more authors specified" unless @authors;

    my $identity := build(%json);
    die "Identity '$identity' must be pinned" unless is-pinned($identity);
    %_<purl> := PURL.from-identity($identity).Str;  # throws if invalid

    %_<mime-type> := "text/plain";
    %_<publisher> := %_<group> := ecosystem($identity);

    my @licenses;
    with %json<license> {
        my %args = acknowledgement => BEGIN Acknowledgement("declared");
        with try LicenseId($_) -> $id {
            %args<id> := $id;
        }
        else {
            %args<name> := $_;
        }
        @licenses = SBOM::License.new(|%args);
    }

    %_<copyright>   := $_ with %json<copyright>;
    %_<description> := $_ with %json<description>;

    my @externalReferences = SBOM::Reference.new(
      :url(rakuland($identity)), :type(BEGIN ReferenceSource("website"))
    );
    with %json<source-url> -> $url {
        @externalReferences.push: SBOM::Reference.new(
          :$url, :type(BEGIN ReferenceSource("source-distribution"))
        );
    }

    my @tags = %json<tags>;

    SBOM::Component.new: :$raw-error,
      :@authors, :@licenses, :@externalReferences, :@tags, |%_
}

#- EXPORT ----------------------------------------------------------------------
my sub EXPORT(*@names) {
    Map.new: @names
      ?? @names.map: {
             if UNIT::{"&$_"}:exists {
                 UNIT::{"&$_"}:p
             }
             else {
                 my ($in,$out) = .split(':', 2);
                 if $out && UNIT::{"&$in"} -> &code {
                     Pair.new: "&$out", &code
                 }
             }
         }  
      !! UNIT::.grep: {
             .key.starts-with('&') && !(.key eq '&EXPORT')
         }
}

#- hack ------------------------------------------------------------------------
# To allow version fetching in test files
unit module SBOM::Raku:ver<0.0.1>:auth<zef:lizmat>;

# vim: expandtab shiftwidth=4
