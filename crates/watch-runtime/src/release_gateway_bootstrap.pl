use strict;
use warnings;
use Fcntl qw(:DEFAULT :mode);
use Digest::SHA;
use File::Temp qw(tempdir);
umask 077;
sub reject { die "gateway_authorization_mismatch: $_[0]\n"; }
sub directory {
    my ($path) = @_;
    $path =~ m{^/} or reject("path is not absolute");
    sysopen(my $dir, "/", O_RDONLY|O_DIRECTORY|O_NOFOLLOW) or reject("cannot open root");
    for my $part (grep { length } split m{/}, $path) {
        $part ne "." && $part ne ".." or reject("invalid path component");
        chdir($dir) or reject("cannot enter approved directory");
        sysopen(my $next, $part, O_RDONLY|O_DIRECTORY|O_NOFOLLOW) or reject("invalid directory or symbolic link");
        $dir = $next;
    }
    chdir($dir) or reject("cannot enter approved directory");
    return $dir;
}
sub pinned {
    my ($source, $expected, $limit, $destination) = @_;
    my ($parent, $name) = $source =~ m{^(.+)/([^/]+)$};
    defined($parent) && $name ne "." && $name ne ".." or reject("invalid source path");
    my $dir = directory($parent);
    sysopen(my $in, $name, O_RDONLY|O_NOFOLLOW|O_NONBLOCK) or reject("cannot open approved file");
    my @stat = stat($in);
    @stat && S_ISREG($stat[2]) && $stat[7] <= $limit or reject("not a bounded regular file");
    my $out;
    if (defined $destination) {
        sysopen($out, $destination, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0600) or reject("cannot create private snapshot");
    }
    my $digest = Digest::SHA->new(256);
    my $bytes = 0;
    while (1) {
        my $n = sysread($in, my $chunk, 65536);
        defined $n or reject("cannot read approved file");
        last unless $n;
        ($bytes += $n) <= $limit or reject("approved file exceeds size bound");
        $digest->add($chunk);
        if (defined $out) { print {$out} $chunk or reject("cannot write private snapshot"); }
    }
    if (defined $out) { close($out) or reject("cannot finish private snapshot"); }
    $digest->hexdigest eq $expected or reject("approved bytes changed");
}
my ($mode, $source, $sha, $prepared, $config_sha, $recovery, $id, $uid, $engine, $previous, $generation) = @ARGV;
@ARGV == 11 && $mode =~ /\A(?:install|commit|rollback)\z/ && $sha =~ /\A[0-9a-f]{64}\z/
    && $id =~ /\A[0-9a-f]{32}\z/ && $uid =~ /\A[1-9][0-9]*\z/
    && $previous =~ /\A(?:absent|[0-9a-f]{64})\z/
    && $generation =~ /\A(?:0|[1-9][0-9]{0,19})\z/ or reject("invalid authorization");
my $tmp = tempdir(".cw-gateway-XXXXXXXX", DIR => "/private/tmp", CLEANUP => 1);
my $broker = "$tmp/watch-gateway-broker";
my @args;
if ($mode eq "install") {
    $config_sha =~ /\A[0-9a-f]{64}\z/ or reject("missing config identity");
    pinned($source, $sha, 128*1024*1024, $broker);
    pinned("$prepared/watch-gateway-broker", $sha, 128*1024*1024, undef);
    pinned("$prepared/config.json", $config_sha, 16384, "$tmp/config.json");
    @args = ("--service-install", "--snapshot", $tmp, "--transaction", $id,
        "--config-sha256", $config_sha, "--broker-sha256", $sha, "--previous-config", $previous,
        "--approval-generation", $generation);
} else {
    # A successful install leaves a protected copy in the existing transaction.
    # If none exists (e.g. cancelled before install), only the original digest
    # can be used to run the baseline/no-op recovery check.
    my $found = eval { pinned($recovery, $sha, 128*1024*1024, $broker); 1 };
    if (!$found) {
        unlink($broker);
        pinned($source, $sha, 128*1024*1024, $broker);
    }
    @args = ("--service-$mode", "--uid", $uid, "--engine", $engine, "--transaction", $id);
    push(@args, "--previous-config", $previous) if $mode eq "rollback";
}
chmod(0500, $broker) == 1 or reject("cannot seal private executable");
chdir($tmp) or reject("private directory unavailable");
# The private snapshot is sealed. The installed broker/config/plist must retain
# the audited public-read modes used by the unprivileged preview and engine.
umask 022;
system { $broker } $broker, @args;
my $status = $?;
chdir("/");
exit($status < 0 || ($status & 127) ? 78 : $status >> 8);
