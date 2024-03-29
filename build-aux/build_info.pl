#!/usr/bin/env perl

# Generate build_info.c.

# Copyright (C) 2009-2011, 2018-2024 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use strict;
use warnings;

use Carp qw(croak);

my $file = shift @ARGV;

{
    my $data = parse_config();
    output_code($data);
}

sub parse_config
{
    my $features = [];
    my $choice_key;
    my $choice = [];
    my $list = $features;

    open(my $fh, '<', "$file.in") or die "Cannot open $file.in: $!";

    while (<$fh>) {
        next if /^\s*$/;

        if ($list eq $choice) {
            unless (s/^\s+//) {
                $list = $features;
                push @$features, [$choice_key, $choice];
                $choice = [];
                undef $choice_key;
            }
        } elsif (/^([A-Za-z0-9_-]+) \s+ choice:\s*$/x) {
            $choice_key = $1;
            $list = $choice;
            next;
        }

        if (/^([A-Za-z0-9_-]+) \s+ (.*)$/x) {
            push @$list, [$1, $2];
        } else {
            croak "Can't parse line: $_";
        }
    }

    if ($list eq $choice) {
        push @$features, [$choice_key, $choice];
    }

    close($fh);

    return $features;
}

sub output_code
{
    my $features = shift;

    open(my $fh, '>', "$file") or die "Cannot open $file: $!";

    print $fh do { local $/; <DATA> }, "\n";
    print $fh <<EOC;
const char *compiled_features[] =
{

EOC
    foreach my $feature (sort { $a->[0] cmp $b->[0] } @$features) {
        my ($name, $check) = @$feature;

        if (ref $check eq 'ARRAY') {
            my ($ch_name, $ch_check) = @{ shift @$check };
            print $fh <<EOC;
#if $ch_check
  "+$name/$ch_name",
EOC
            foreach my $choice (@$check) {
                ($ch_name, $ch_check) = @$choice;

                print $fh <<EOC;
#elif $ch_check
  "+$name/$ch_name",
EOC
            }
                print $fh <<EOC;
#else
  "-$name",
#endif

EOC
        } else {
            print $fh <<EOC;
#if $check
  "+$name",
#else
  "-$name",
#endif

EOC
        }
    }
    print $fh <<EOC;

  /* sentinel value */
  NULL
};


EOC
}

__DATA__
/* Autogenerated by build_info.pl - DO NOT EDIT */

/* This stores global variables that are initialized with
   preprocessor declarations for output with the --version flag.

   Copyright (C) 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003,
   2004, 2005, 2006, 2007, 2008, 2009 Free Software Foundation, Inc.  */

#include "wget.h"
#include <stdio.h>
#include "version.h"
