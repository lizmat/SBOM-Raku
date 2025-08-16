use JSON::Fast:ver<0.19+>:auth<cpan:TIMOTIMO>;
use OpenSSL::Digest:ver<0.2.5+>:auth<zef:raku-community-modules>;
use PURL:ver<0.0.14+>:auth<zef:lizmat>;
use Rakudo::CORE::META:ver<0.0.12+>:auth<zef:lizmat>;

use Identity::Utils:ver<0.0.28+>:auth<zef:lizmat> <
  auth build meta dependencies-from-meta distribution-name
  ecosystem is-pinned issue-tracker-url raku-land-url short-name
  source-distribution-url ver
>;
use String::Utils:ver<0.0.36+>:auth<zef:lizmat> <
  after before describe-Version
>;

use SBOM::CycloneDX:ver<0.0.15+>:auth<zef:lizmat>;
use SBOM::enums:ver<0.0.15+>:auth<zef:lizmat> <
  Acknowledgement ComponentType HashAlgorithm LicenseId Phase
  ReferenceSource Scope
>;
use SBOM::subsets:ver<0.0.15+>:auth<zef:lizmat> <
  email
>;

# Quick lookup of hash creation/mapping logic
my constant @hashers = <MD5 SHA-1 SHA-256 SHA-384 SHA-512>;
my constant %hasher = @hashers.map: {
    $_ => ::("\&$_.lc.subst('-')-hex")  # UNCOVERABLE
}
my constant %hashnum = @hashers.map: {
    $_ => HashAlgorithm($_)  # UNCOVERABLE
}

#- helper subs -----------------------------------------------------------------
my sub reference($url, $type) {
    SBOM::Reference.new(
      :$url,
      :type($type ~~ Str ?? ReferenceSource($type) !! $type)
    )
}

#- contact ---------------------------------------------------------------------
my %contact;
my $contact-lock := Lock.new;

# Handle creation of an SBOM::Contact object
my sub contact(Str:D $string) {
    
    # Produce a Contact object
    my sub produce-contact() {
        my $bom-ref := $string.subst(/ \W+ /, :global);
        return $_ with %contact{$bom-ref};

        my $name = $string;
        my $email;
        for $string.words -> $part {
            if $part.starts-with('<')
              && $part.ends-with('>')
              && $part.substr(1, *-1) ~~ email {  # UNCOVERABLE
                $email = $part.substr(1, *-1);
                $name  = $string.subst($part).trim;
                last;
            }
        }

        %contact{$string} := SBOM::Contact.new(
          :$bom-ref, :$name, :$email, :raw-error
        )
    }

    # Make sure checking/updating the cache is thread-safe
    $contact-lock
      ?? $contact-lock.protect: &produce-contact
      !! produce-contact
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
my multi sub licenses(Str:D $license) { licenses((:$license).Map) }
my multi sub licenses(%json) {
    with %json<license> -> $license {
        my %args = acknowledgement => BEGIN Acknowledgement("declared");
        with try LicenseId($license) -> $id {
            %args<id>  := $id;  # UNCOVERABLE
            %args<url> := $_ with $id.url;
        }
        else {
            %args<name> := $license;
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
  :$bom-ref,
  *%in
) {
    my %out;
    %out<type>  := ComponentType(%json<type> // $type);   # throws if invalid
    %out<scope> := Scope(       %json<scope> // $scope);  # throws if invalid

    %out<name>    := %json<name>    // die "Name must be specified";
    %out<version> := %json<version> // die "Version must be specified";

    authors( %json, %out);
    licenses(%json, %out);

    my $identity := build(%json);
    die "Identity '$identity' must be pinned" unless is-pinned($identity);
    my $purl := PURL.from-identity($identity).Str;  # throws if invalid
    %out<purl>    := $purl;  # UNCOVERABLE
    %out<bom-ref> := $bom-ref // $purl;

    %out<mime-type> := "text/plain";
    %out<group>     := auth($identity);
    %out<publisher> := ecosystem($identity);

    %out<copyright>   := $_ with %json<copyright>;
    %out<description> := $_ with %json<description>;

    my @externalReferences = reference(
      raku-land-url($identity),
      BEGIN ReferenceSource("documentation")
    );
    my sub add-reference($url, $type) {
        @externalReferences.push: reference $url, $type
    }
    my sub add-source-references($url is copy, :$no-issue-tracker) {
        $url .= subst(".git");

        add-reference $url, BEGIN ReferenceSource("distribution");

        if issue-tracker-url($url) -> $tracker-url {
            add-reference(
              $tracker-url, BEGIN ReferenceSource("issue-tracker")
            ) unless $no-issue-tracker;
        }

        if source-distribution-url($url, %out<version>) -> $dist-url {
            add-reference
              $dist-url, BEGIN ReferenceSource("source-distribution");
        }
    }

    with %json<support> -> %support {
        with %support<email> -> $email {
            add-reference "mailto:$email", BEGIN ReferenceSource("support");
        }
        with %support<mailinglist> -> $url {
            add-reference $url, BEGIN ReferenceSource("mailing-list");
        }
        with %support<bugtracker> -> $url {
            add-reference $url, BEGIN ReferenceSource("issue-tracker");
        }
        with %support<source> -> $url {
            add-source-references
              $url,
              :no-issue-tracker(%support<bugtracker>);
        }
        with %support<irc> -> $url {
            add-reference
              $url
                .subst('irc.freenode.net','libera.chat')
                .subst('perl6','raku'),
              BEGIN ReferenceSource("chat");
        }
        with %support<phone> -> $phone {
            add-reference
              "tel:$phone",
              BEGIN ReferenceSource("security-contact");
        }
    }
    orwith %json<source-url> -> $url {
        add-source-references $url;
    }
    with %out<licenses> -> @licenses {
        add-reference(.license.url, BEGIN ReferenceSource("license"))
          for @licenses;
    }
    %out<externalReferences> := @externalReferences.sort(*.type).List;

    %out<tags> := %json<tags> // ();

    %out
}

#- tools -----------------------------------------------------------------------
my $tools := BEGIN SBOM::Tool.new(:components(component($?DISTRIBUTION.meta),));

#- metadata --------------------------------------------------------------------
my sub metadata(|c) { SBOM::Metadata.new: |metadata-hash(|c), :raw-error }

my proto sub metadata-hash(|) {*}
my multi sub metadata-hash(IO() $io, *%args) {
    metadata-hash from-json($io.slurp, :immutable), |%args
}
my multi sub metadata-hash(
   %json,
  :$timestamp,
  :$phase = "pre-build",
  *%in,
) {
    my %out;
    %out<timestamp>  := $_ with $timestamp;
    %out<lifecycles> := (SBOM::Lifecycle.new(:$phase),);
    %out<tools>      := $tools;

    my $component  := %out<component> := component(%json, |%in);
    %out<authors>  := $_ with $component.authors;
    %out<licenses> := $_ with $component.licenses;

    %out
}

#- VM-component ----------------------------------------------------------------
my sub VM-component() {
    my $name := $*VM.name;
    $name eq 'moar'
      ?? MoarVM-component()
      !! die "No support for VM '$name' yet"
}

my sub MoarVM-component() {
    my $VM      := $*VM;
    my $VM-name := $VM.name;
    my $VM-auth := $VM.auth;
    my $VM-url  := "https://github.com/MoarVM/MoarVM.git";
    my $VM-vers := describe-Version($VM.version);
    my $VM-sha  := after($VM-vers,"g") // $VM-vers;

    SBOM::Component.new:
      bom-ref     => $VM-name,
      type        => ComponentType("platform"),
      scope       => Scope("required"),
      authors     => [contact($VM-auth)],
      name        => $VM-name.tc,
      description => $VM.desc,
      copyright   => "© 2012 - {DateTime.now.year} Jonathan Worthington",
      group       => $VM-auth,
      publisher   => $VM-auth,
      version     => $VM-vers,
      licenses    => licenses("Artistic-2.0"),
      externalReferences => (
        reference($VM-url.subst(".git"),      "distribution"),
        reference(issue-tracker-url($VM-url), "issue-tracker"),
        reference("irc://libera.chat/moarvm", "chat"),
        reference(
          source-distribution-url($VM-url, $VM-sha), "source-distribution"
        ),
      )
}

#- Rakudo-component ------------------------------------------------------------
my sub Rakudo-component() {
    my %META    := %Rakudo::CORE::META;
    my %support := %META<support>;

    SBOM::Component.new:
      bom-ref     => %META<name>.subst(/ \s+ /, :global),
      type        => ComponentType("platform"),
      scope       => Scope("required"),
      authors     => %META<authors>.map(&contact).List,
      name        => %META<name>,
      description => %META<description>,
      copyright   => "© 2006 - {DateTime.now.year} %META<auth>",
      group       => %META<authors>.head,
      publisher   => %META<authors>.head,
      version     => %META<version>,
      licenses    => licenses(%META),
      externalReferences => (
        reference("https://github.com/rakudo/rakudo", "distribution"),
        reference(%support<bugtracker>,               "issue-tracker"),
        reference(%support<source>,                   "source-distribution"),
        reference(%support<irc>,                      "chat"),
      )
}

#- source-sbom -----------------------------------------------------------------
my sub source-sbom(Any:D $source, *%_) {
    SBOM::CycloneDX.new: |source-sbom-hash($source, |%_), :raw-error
}

my proto sub source-sbom-hash(|) {*}
my multi sub source-sbom-hash(IO() $io, *%_) {
    source-sbom-hash from-json($io.slurp, :immutable), |%_
}
my multi sub source-sbom-hash(
   %json,
  :$version = 1,
  :$all-dependencies,
  *%in
) {
    my %out := SBOM::CycloneDX.Hash;

    %out<version> := $version;  # UNCOVERABLE

    my sub purlize($requirement) { PURL.from-identity($requirement).Str }

    # Initialize lookups with Rakudo / VM components / dependencies
    my $vm-component     := VM-component;
    my $rakudo-component := Rakudo-component;
    my %components = ($vm-component, $rakudo-component).map: { .bom-ref => $_ }
    my %refs =
      $tools.components.head.bom-ref => %(  # tool depends on Rakudo
        $rakudo-component.bom-ref => $rakudo-component.name
      ),
      $rakudo-component.bom-ref => %(       # Rakudo depends on VM
        $vm-component.bom-ref => $vm-component.name
      );

    # Recursively find dependencies
    for dependencies-from-meta(%json, :stage<all>) -> $requirement {
        # Can find this
        with $requirement && meta($requirement) -> %json {

            my $bom-ref           := purlize $requirement;
            %components{$bom-ref} := component %json, :$bom-ref;
            %refs{$bom-ref}       := my %dependencies;

            my sub fetch-dependencies(%meta) {
                for dependencies-from-meta(%meta) -> $requirement {
                    with meta($requirement) -> %json {
                        my $bom-ref             := purlize $requirement;
                        %dependencies{$bom-ref} := build %json;  # XXX requirement vs selected identity

                        # An unseen component, recurse
                        unless %components{$bom-ref} {
                            %components{$bom-ref} := component %json, :$bom-ref;
                            fetch-dependencies(%json)
                        }
                    }
                }
            }
            fetch-dependencies(%json);
        }
    }

    %out<dependencies> := %refs.keys.sort.map(-> $ref {
        SBOM::Dependency.new(:$ref, :dependsOn(%refs{$ref}.keys.sort.List))
    }).List;
    %out<components> := %components.sort(*.key).map(*.value).List;

    my $metadata := %out<metadata> := metadata(%json, |%in);
    %out<externalReferences> := $metadata.component.externalReferences;

    %out
}

#- tar-sbom --------------------------------------------------------------------
my sub tar-sbom(IO() $io, *%_) {
    SBOM::CycloneDX.new: |tar-sbom-hash($io, |%_), :raw-error
}

my sub tar-sbom-hash(IO() $io, *%in) {
    die "'$io' does not exist" unless $io.e;

    # Some tar files have an upper directory, so we need to search
    my $proc := run "tar", "tf", $io, :err, :out;
    die $proc.err.slurp(:close) if $proc.exitcode;

    # Try to extract the META6.json from the tar file
    my $path := $proc.out.lines(:close).first(*.ends-with("META6.json"));
       $proc := run "tar", "xf", $io, "--to-stdout", $path, :err, :out;
    die $proc.err.slurp(:close) if $proc.exitcode;

    # Create a hash to work with
    my $json := $proc.out.slurp(:close);
    my %out  := source-sbom-hash(from-json($json), |%in);

    # Put in the hashes
    my $metadata  := %out<metadata>;
    my %component := $metadata.component.Hash;
    %component<hashes> := @hashers.map({
        SBOM::HashedString.new: :alg(%hashnum{$_}), :content(%hasher{$_}($io))
    }).List;

    # Create a new Metadata object with updated component
    %out<metadata> := $metadata.update-component(
      SBOM::Component.new(|%component, :raw-error)
    );

    %out
}

#- produce-source-sbom ---------------------------------------------------------
my constant $SOURCE-cdx-json = 'SOURCE.cdx.json';
my sub produce-source-sbom(
  IO() $io,
  IO() $sbom-io = $io.sibling(".META/$SOURCE-cdx-json");
      :&created = -> $ { },
      :&updated = -> $ { },
      :&error   = -> $, $ { },
--> Nil) {

    with (try source-sbom($io)) -> $sbom {
        (my $dir := $sbom-io.parent).mkdir;
        my $existed := $sbom-io.s;

        $sbom-io.spurt($sbom.JSON);
        if $sbom-io.s {
            if $existed {
                updated($io);
            }
            else {
                indir $dir, {
                    my $proc := run <git add>, $sbom-io.basename, :out, :err;
                    note $proc.err.slurp.chomp if $proc.exitcode;
                }
                created($io)
            }
        }
        else {
            error($io, "Does not exist");
        }
    }
    else {
        error($io, $!);
    }
}

#- modernize-META6 -------------------------------------------------------------
my sub modernize-META6(
  IO()  $io,
  IO()  $destination-io = $io,
  Bool :$production,
  Str  :$auth,
       :&changed = -> $ { },
       :&error   = -> $, $ { },
--> Nil) {
    my $changed;
    sub mark-as-changed() { $changed = True }

    with (try from-json($io.slurp)) -> %json {

        # Logic to preserve old-style depends info
        my @build-depends = %json<build-depends>:delete:v;
        my @test-depends  = %json<test-depends>:delete:v;
        sub keep-old-depends() {
            my %depends := %json<depends>;
            %depends<build><requires> := @build-depends if @build-depends;
            %depends<test><requires>  := @test-depends  if @test-depends;
            mark-as-changed;
        }

        without %json<auth> -> $new is raw {
            if $auth {
                $new = $auth;  # UNCOVERABLE
                mark-as-changed;
            }
            orwith try from-json(
              $*HOME.add("/.fez-config.json").slurp, :immutable
            )<un> {
                $new = "zef:$_";
                mark-as-changed;
            }
        }

        without %json<authors> {
            $_ = my @authors;
            with %json<author>:delete {
                @authors.push($_);
                mark-as-changed;
            }
        }

        with $production {
            unless %json<production> eqv $_ {
                %json<production> = $_;  # UNCOVERABLE
                mark-as-changed;
            }
        }

        without %json<raku> {
            $_ = %json<perl>:delete // "6.d";
            mark-as-changed;
        }

        with %json<perl> {
            %json<perl>:delete;
            mark-as-changed;
        }

        with %json<resources> {
            unless .elems {
                %json<resources>:delete;
                mark-as-changed;
            }
        }

        my $source-url = %json<source-url>:delete;

        if %json<support> -> %support {
            if $source-url {
                without %support<bugtracker> {
                    $_ = issue-tracker-url($source-url);
                    mark-as-changed;
                }

                without %support<source> {
                    $_ = $source-url;
                    mark-as-changed;
                }
            }
        }
        elsif $source-url {  # UNCOVERABLE
            %json<support> = {  # UNCOVERABLE
              bugtracker => issue-tracker-url($source-url),
              source     => $source-url
            }
            mark-as-changed;
        }

        with %json<depends> -> $depends is raw {
            $depends = [$depends] if $depends ~~ Str;

            # An array is old style, so convert to new
            if $depends ~~ Positional && $depends.elems {
                my %depends;
                %depends<runtime><requires> := $depends<>;
                $depends = %depends;
                keep-old-depends if @build-depends || @test-depends;
            }
        }

        # No "depends" yet, but we haz other old-style dependencies
        elsif @build-depends || @test-depends {
            %json<depends> := my %depends;
            keep-old-depends;
        }

        # Changes made, so update and mark as updated
        if $changed {
            $destination-io.spurt: to-json(%json, :pretty, :sorted-keys);
            changed($destination-io)
        }
    }
    else {
        error($io, $!);
    }
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
           authors component component-hash contact licenses metadata
           metadata-hash modernize-META6 produce-source-sbom
           Rakudo-component source-sbom source-sbom-hash tar-sbom
           tar-sbom-hash VM-component
         >.map({  # UNCOVERABLE
             "&$_" => UNIT::{"&$_"}  # UNCOVERABLE
         }).Map
}

#- hack ------------------------------------------------------------------------
# To allow version fetching in test files
unit module SBOM::Raku:ver<0.0.12>:auth<zef:lizmat>;

# vim: expandtab shiftwidth=4
