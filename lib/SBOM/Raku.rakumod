use JSON::Fast:ver<0.19+>:auth<cpan:TIMOTIMO>;
use SBOM::CycloneDX:ver<0.0.9+>:auth<zef:lizmat>;

use Identity::Utils:ver<0.0.24+>:auth<zef:lizmat> <
  auth build meta dependencies-from-depends ecosystem is-pinned
  raku-land-url short-name ver
>;
use SBOM::enums:ver<0.0.8+>:auth<zef:lizmat> <
  Acknowledgement ComponentType LicenseId Phase ReferenceSource Scope
>;
use SBOM::subsets:ver<0.0.8+>:auth<zef:lizmat> <
  email
>;
use String::Utils:ver<0.0.35+>:auth<zef:lizmat> <
  sha1
>;
use PURL:ver<0.0.6+>:auth<zef:lizmat>;

#- helper subs -----------------------------------------------------------------
my %contact;
my $contact-lock := Lock.new;

# Handle creation of an SBOM::Contact object
my sub contact(Str:D $string) {

    # Make sure checking/updating the cache is thread-safe
    $contact-lock.protect: {
        my $bom-ref := $string.subst(/ \W+ /, :global);
        return $_ with %contact{$bom-ref};

        my $name = $string;;
        my $email;
        for $string.words -> $part {
            if $part.starts-with('<')
              && $part.ends-with('>')
              && $part.substr(1, *-1) ~~ email {
                $email = $part.substr(1, *-1);
                $name  = $string.subst($part).trim;
                last;
            }
        }

        %contact{$string} := SBOM::Contact.new(
          :$bom-ref, :$name, :$email, :raw-error
        )
    }
}

#- authors ---------------------------------------------------------------------
my proto sub authors(|) {*}
my multi sub authors(%json) {
    (%json<authors> || %json<author>).map(&contact).List
}
my multi sub authors(%json, %out) {
    if authors(%json) -> @authors {
        %out<authors> := @authors
    }
    else {
        die "Must have one or more authors specified";
    }
}

#- licenses --------------------------------------------------------------------
my proto sub licenses(|) {*}
my multi sub licenses(%json) {
    with %json<license> {
        my %args = acknowledgement => BEGIN Acknowledgement("declared");
        with try LicenseId($_) -> $id {
            %args<id> := $id;
        }
        else {
            %args<name> := $_;
        }
        (SBOM::License.new(
          license => SBOM::LicenseInfo.new(|%args, :raw-error)
        ),)
    }
    else {
        ()
    }
}
my multi sub licenses(%json, %out) {
    %out<licenses> := licenses(%json)
}

#- metadata --------------------------------------------------------------------
my sub metadata(|c) { SBOM::Metadata.new: |metadata-hash(|c), :raw-error }

my proto sub metadata-hash(|) {*}
my multi sub metadata-hash(IO() $io, *%args) {
    metadata-hash from-json($io.slurp, :immutable), |%args
}
my multi sub metadata-hash(
   %json,
  :$timestamp = DateTime.now,
  :$phase     = "build",
  *%in,
) {
    my %out;
    %out<timestamp>  := $timestamp;
    %out<lifecycles> := (SBOM::Lifecycle.new(:$phase),);

    my $component  := %out<component> := component(%json, |%in);
    %out<authors>  := $_ with $component.authors;
    %out<licenses> := $_ with $component.licenses;

    %out
}

#- component -------------------------------------------------------------------
my sub component(|c) { SBOM::Component.new: |component-hash(|c), :raw-error }

my proto sub component-hash(|) {*}
my multi sub component-hash(IO() $io, *%in) {
    component-hash from-json($io.slurp, :immutable), |%in
}
my multi sub component-hash(
   %json,
  :$type  = "library",
  :$scope = "required",
  *%in
) {
    my %out;
    %out<type>  := ComponentType($type);  # throws if invalid
    %out<scope> := Scope($scope);         # throws if invalid

    %out<name>    := %json<name>    // die "Name must be specified";
    %out<version> := %json<version> // die "Version must be specified";

    authors( %json, %out);
    licenses(%json, %out);

    my $identity := build(%json);
    die "Identity '$identity' must be pinned" unless is-pinned($identity);
    my $purl := PURL.from-identity($identity).Str;  # throws if invalid
    %out<bom-ref> := %out<purl> := $purl;

    %out<mime-type> := "text/plain";
    %out<group>     := auth($identity);
    %out<publisher> := ecosystem($identity);

    %out<copyright>   := $_ with %json<copyright>;
    %out<description> := $_ with %json<description>;

    my @externalReferences = SBOM::Reference.new(
      :url(raku-land-url($identity)), :type(BEGIN ReferenceSource("website"))
    );
    with %json<source-url> -> $url {
        @externalReferences.push: SBOM::Reference.new(
          :$url, :type(BEGIN ReferenceSource("source-distribution"))
        );
    }
    %out<externalReferences> := @externalReferences.List;

    %out<tags> := %json<tags> // ();

    %out
}

#- sbom ------------------------------------------------------------------------
my sub sbom(|c) { SBOM::CycloneDX.new: |sbom-hash(|c), :raw-error }

my proto sub sbom-hash(|) {*}
my multi sub sbom-hash(IO() $io, *%in) {
    sbom-hash from-json($io.slurp, :immutable), |%in
}
my multi sub sbom-hash(
   %json,
  :$version = 1,
  :$all-dependencies,
  *%in
) {
    my %out := SBOM::CycloneDX.Hash;

    %out<version> := $version;

    # Code to recursively find dependencies
    my %components;
    my %refs;
    for dependencies-from-depends(%json<depends>) -> $requirement {

        # Can find this
        with meta($requirement) -> %json {

            # Dependency spec may differ from identity selected
            my $ref           := build %json;
            %components{$ref} := component %json;
            %refs{$ref}       := my @dependencies;

            my sub fetch-dependencies($depends) {
                for dependencies-from-depends($depends) -> $requirement {
                    with meta($requirement) -> %json {
                        my $ref := build %json;
                        @dependencies.push($ref);

                        # An unseen component, recurse
                        unless %components{$ref} {
                            %components{$ref} := component %json;
                            fetch-dependencies(%json<depends>)
                        }
                    }
                }
            }
            fetch-dependencies(%json<depends>);
        }
    }

    %out<dependencies> := %refs.keys.sort.map(-> $ref {
        SBOM::Dependency.new(:$ref, :dependsOn(%refs{$ref}))
    }).List;
    %out<components> := %components.sort(*.key).map(*.value).List;

    my $metadata := %out<metadata> := metadata(%json, |%in);
    %out<externalReferences> := $metadata.component.externalReferences;

    %out
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
      !! <
           authors component component-hash licenses metadata
           metadata-hash sbom sbom-hash
         >.map({
             "&$_" => UNIT::{"&$_"}
         }).Map
}

#- hack ------------------------------------------------------------------------
# To allow version fetching in test files
unit module SBOM::Raku:ver<0.0.3>:auth<zef:lizmat>;

# vim: expandtab shiftwidth=4
