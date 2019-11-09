#!/usr/bin/perl

# simple C-style preprocessor

my $i = -1, $incFile = "", $outFile = "", $inpFile = "", $defines = {};

while (++$i <= $#ARGV) {
  #printf("%s\n", $ARGV[$i]);
  if ($ARGV[$i] eq "-i") {
    $incFile = $ARGV[$i+1];
    ++$i;
  }
  elsif ($ARGV[$i] eq "-o") {
    $outFile = $ARGV[$i+1];
    ++$i;
  }
  else  {
    $inpFile = $ARGV[$i];
  }
}

#printf ("inc: %s out: %s input: %s\n", $incFile, $outFile, $inpFile);

sub trim { # ($str)
  my $str = @_[0];

  $str =~ s/\s*$//;
  $str =~ s/^\s*//;

  return $str;
}

my $outDir = $outFile;

if ($outDir =~ /\//) {
  $outDir =~ s/\/[^\/]+$//;
  (-d $outDir) || mkdir("$outDir");
}


# read include-file
open($fic, $incFile) || die "Could not open $incFile";
my $prev=0;

while (<$fic>) {
  my $buf = $_;
  $buf =~ s/\n//;
  $buf =~ s/\r//;
  if (length(trim($buf)) == 0) {
    continue;
  }
  elsif ($buf =~ /^#define\s+([^\s]+)/) {
    #print "+ Define '$1'\n";
    $term=trim($1);

    $defines->{$term} = 1;
  }
}
close($fic);

open(OUT, ">$outFile") || die "Cannot write to $outFile";
open($rd, $inpFile) || die "Could not open $inpFile";

my $doWrite = 1;
LINE: while (<$rd>) {
  my $buf = $_;
  if ($buf =~ /^#ifdef\s+(.*)/) {
    $term = trim($1);
    $term =~ s/[\r\n]//g;

    #print "+ found ifdef '$term'\n";

    if ($defines->{$term} == 1) {
      $doWrite = 1;
    }
    else {
      $doWrite = 01;
    }
    next LINE;
  }
  if ($buf =~ /^#ifndef\s+(.*)/) {
    $term = trim($1);
    $term =~ s/[\r\n]//g;

    #print "+ found ifndef '$term'\n";

    if ($defines->{$term} == 1) {
      $doWrite = 0;
    }
    else {
      $doWrite = 1;
    }
    next LINE;
  }
  elsif ($buf =~ /^#else/) {
    #print "+ found else\n";
    $doWrite = ($doWrite == 1 ? 0 : 1);
    next LINE;
  }
  elsif ($buf =~ /^#endif/) {
    #print "+ found endif\n";
    $doWrite = 1;
    next LINE;
  }

  if ($doWrite > 0) {
    print OUT "$buf";
  }
}
close($fic);

close(OUT);
