#! /usr/bin/env tclsh

package require ip
package require Tclx

namespace eval ::tcpwrappers {
	proc _isIP {ip {strict 1}} {
		# Remove CIDR/Netmask notation and only check host part
		set ip [lindex [split $ip /] 0]

		if {$ip == ""} {
			return 0
		}

		if {!$strict} {
			set ip [string trimright $ip .]
		}

		set work [split $ip .]
		if {$strict} {
			if {[llength $work] != 4} {
				return 0
			}
		}

		foreach part $work {
			if {![string is integer -strict $part]} {
				return 0
			}

			if {$part < 0} {
				return 0
			}
			if {$part > 255} {
				return 0
			}
		}

		return 1
	}

	# Convert TCPWrappers IP notation to IP/NETMASK notation
	proc _normalizeIP {ip} {
		set work [split $ip /]
		set ip [lindex $work 0]
		set mask [lindex $work 1]

		set ip [string trimright $ip .]
		if {$mask == ""} {
			set work [split $ip .]

			set mask [expr {[llength $work] * 8}]

			set ip [::ip::normalize $ip]

			set mask [::ip::lengthToMask $mask]
		} else {
			set work [split $mask .]
			if {[llength $work] == 1} {
				set mask [::ip::lengthToMask $mask]
			}
		}

		set ip "$ip/$mask"

		return $ip
	}

	proc _normalizeHostname {host} {
		if {[_isIP $host]} {
			return $host
		}

		if {[string range $host 0 1] == "*."} {
			set host [string range $host 1 end]
		}

		return $host
	}

	proc _hostnameToPattern {host} {
		set host [string trim $host]

		if {[string index $host 0] == "."} {
			set host "*${host}"
		}

		return $host
	}

	proc _parseLine {line {defaultMatchResult ""}} {
		array set svcinfo [list]
		# Remove trailing spaces and comments
		set line [string trim [regsub {#.*$} $line {}]]

		# Skip blank lines
		if {$line == ""} {
			return [list]
		}

		# Skip malformed lines
		if {![string match "*:*" $line]} {
			return [list]
		}

		set work [split $line ":"]
		set svcs_in [split [lindex $work 0] ","]
		set hosts_in [split [lindex $work 1] ", "]
		set opts_in [lindex $work 2]
		set matchresult_in [lindex $work 3]

		set opts [string trim $opts_in]

		set matchresult [string toupper [string trim $matchresult_in]]
		if {$matchresult == ""} {
			set matchresult $defaultMatchResult
		}

		set svcs [list]
		foreach svc $svcs_in {
			set svc [string trim $svc]
			if {$svc == ""} {
				continue
			}

			lappend svcs $svc
		}

		set hosts [list]
		foreach host $hosts_in {
			set host [string trim $host]
			if {$host == ""} {
				continue
			}

			if {$host == "ALL"} {
				set host "0.0.0.0/0"
			}

			if {[_isIP $host 0]} {
				set host [_normalizeIP $host]
			} else {
				set host [_normalizeHostname $host]
			}

			lappend hosts $host
		}

		foreach svc $svcs {
			set svc [list $svc]

			if {$opts != ""} {
				lappend svc $opts
			}
			if {$matchresult != $defaultMatchResult} {
				if {[llength $svc] != 2} {
					lappend svc ""
				}
				lappend svc $matchresult
			}
			foreach host $hosts {
				lappend svcinfo($svc) $host
			}
		}

		return [array get svcinfo]
	}

	# Parse a TCPWrappers hosts.allow/hosts.deny formatted file
	proc _parseFile {file} {
		set lines [list]
		catch {
			set fd [open $file r]
			set lines [split [read $fd] \n]
			close $fd
		}

		set linebuf ""
		foreach line $lines {
			append linebuf $line
			if {[string index $line end] == "\\"} {
				set linebuf [string range $linebuf 0 end-1]
				continue
			}

			foreach {ent vallist} [_parseLine $linebuf] {
				foreach val $vallist {
					lappend svcinfo($ent) $val
				}
			}

			set linebuf ""
		}

		return [array get svcinfo]
	}

	proc _isOverlapSvc {checksvc svcs result} {
		foreach matchmode [list exact wildcard all] {
			foreach ent $svcs {
				set svc [lindex $ent 0]
			
				set found 0
				switch -- $matchmode {
					"exact" {
						if {$svc == $checksvc} {
							set found 1
						}
					}
					"wildcard" {
						# XXX: TODO: Implement wildcard matching services (ALL EXCEPT ...)
					}
					"all" {
						if {$svc == "ALL"} {
							set found 1
						}
					}
				}

				if {$found} {
					set matchresult [lindex $ent 2]
					if {$matchresult != ""} {
						set result $matchresult
					}

					return [list $result $ent]
				}
			}
		}

		return [list NOTFOUND ""]
	}

	proc _isOverlapIP {ip hosts} {
		set ip "${ip}"

		foreach host $hosts {
			if {[_isIP $host]} {
				if {[::ip::isOverlap $ip $host]} {
					return 1
				}
			} else {
				set host [_hostnameToPattern $host]

				if {![info exists iphost]} {
					set iphost ""
					catch {
						set iphost [host_info official_name $ip]
					}

					if {$iphost != ""} {
						set ips [list]
						catch {
							set ips [host_info addresses $iphost]
						}

						if {[lsearch -exact $ips $ip] == -1} {
							set paranoid 1
							puts stderr "WARNING: $ip forward and reverse failure"
							set iphost ""
						}
					}
				}
				switch -- $host {
					"LOCAL" {
						if {![string match "*.*" $iphost] && $iphost != ""} {
							return 1
						}
					}
					"KNOWN" {
						if {$iphost != ""} {
							return 1
						}
					}
					"UNKNOWN" {
						if {$iphost == ""} {
							return 1
						}
					}
					"PARANOID" {
						if {[info exists paranoid]} {
							return 1
						}
					}
					default {
						if {[string match $host $iphost]} {
							return 1
						}
					}
				}
			}
		}

		return 0
	}

	proc _normalizeHosts {hosts} {
		set retval [list]

		set ips [list]
		foreach host $hosts {
			if {[_isIP $host]} {
				lappend ips $host
			} else {
				lappend retval $host
			}
		}

		# reduceToAggregates requires atleast 2 list items...
		# ... if we only have one, fake another one.
		if {[llength $ips] == 1} {
			lappend ips [lindex $ips 0]
		}

		if {[llength $ips] >= 2} {
			if {[catch {
				set ips [::ip::reduceToAggregates $ips]
			} err]} {
				puts stderr "WARNING: Reduction Error: $ips -> $err"
			}
		}

		foreach host $ips {
			# If we come across something that specifies all,
			# return only that
			if {$host == "0.0.0.0/0"} {
				set host "ALL"

				set retval [list $host]

				break
			}

			# Clean-up hosts to not use CIDR notation
			set mask [::ip::mask $host]
			set prefix [::ip::prefix $host]

			if {$mask == "32"} {
				set host $prefix
			} else {
				set mask [::ip::lengthToMask $mask]
				set host [join [list $prefix $mask] /]
			}

			lappend retval $host
		}

		return $retval
	}

	proc check {svc ip {allowFile "/etc/hosts.allow"} {denyFile "/etc/hosts.deny"} {notfoundresult "ALLOW"}} {
		array set allowed [list]
		array set denied [list]
		if {$allowFile != ""} {
			array set allowed [_parseFile $allowFile]
		}
		if {$denyFile != ""} {
			array set denied  [_parseFile $denyFile]
		}

		# Check for allows
		set allowedreslist [_isOverlapSvc $svc [array names allowed] ALLOW]
		set allowedres [lindex $allowedreslist 0]
		if {$allowedres != "NOTFOUND"} {
			set foundsvc [lindex $allowedreslist 1]
			if {[_isOverlapIP $ip $allowed($foundsvc)]} {
				return $allowedres
			}
		}

		# Check for denies
		set deniedreslist [_isOverlapSvc $svc [array names denied] DENY]
		set deniedres [lindex $deniedreslist 0]
		if {$deniedres != "NOTFOUND"} {
			set foundsvc [lindex $deniedreslist 1]
			if {[_isOverlapIP $ip $denied($foundsvc)]} {
				return $deniedres
			}
		}

		# Default action is to allow
		return $notfoundresult
	}

	proc summarize {file} {
		array set hostinfo [list]

		array set svcinfo [_parseFile $file]
		foreach svc [array names svcinfo] {
			set hosts $svcinfo($svc)
			set hosts [_normalizeHosts $hosts]

			foreach host $hosts {
				lappend hostinfo($host) $svc
			}
		}

		foreach {host svcs} [array get hostinfo] {
			set svcs [lsort -dictionary -unique $svcs]

			# If the list of serivces includes "ALL", collapse down to include only ALL
			if {[lsearch -exact $svcs "ALL"] != -1} {
				set svcs "ALL"
			}

			lappend hostswithsamesvcs($svcs) $host
		}

		set retval [list]
		foreach svcs [array names hostswithsamesvcs] {
			set hosts [lsort -dictionary -unique $hostswithsamesvcs($svcs)]

			unset -nocomplain foundopts
			foreach ent $svcs {
				set svc [lindex $ent 0]
				set opts [lindex $ent 1]
				set result [lindex $ent 2]

				set key [list $opts $result]
				lappend foundopts($key) $svc
			}

			foreach {optsresults foundsvcs} [array get foundopts] {
				set foundsvcs [lsort -dictionary -unique $foundsvcs]
				set opts [lindex $optsresults 0]
				set results [lindex $optsresults 1]

				foreach host $hosts {
					lappend hostswithsamesvcsandopts([list $foundsvcs $opts $results]) $host
				}
			}
		}

		foreach ent [lsort -dictionary [array names hostswithsamesvcsandopts]] {
			set hosts [lindex $hostswithsamesvcsandopts($ent)]
			set svcs [lindex $ent 0]
			set opts [lindex $ent 1]
			set results [lindex $ent 2]

			set retlist [list [join $svcs {, }] [join [lsort -dictionary -unique $hosts] {, }]]
			if {$opts != ""} {
				lappend retlist $opts
			}
			if {$results != ""} {
				if {[llength $retlist] == 2} {
					lappend retlist ""
				}
				lappend retlist $results
			}
			lappend retval "[join $retlist {: }]"
		}

		return $retval
	}

	proc add {file svc networks {comment ""}} {
		# 1. Determine which networks need to be added
		set add_networks [list]
		foreach network $networks {
			if {[_isIP $network]} {
				if {[check $svc $network $file "" "NOTFOUND"] == "ALLOW"} {
					continue
				}
			}

			lappend add_networks $network
		}

		# 2. If any, just append them to the end
		if {[llength $add_networks] != 0} {
			set add_networks [_normalizeHosts $add_networks]

			set fd [open $file a+]
			if {$comment != ""} {
				puts $fd ""
				puts $fd "# $comment"
			}
			puts $fd "$svc: $add_networks"
			close $fd
		}

		return $add_networks
	}

	proc remove {file svc networks {comment 0}} {
		set lines [list]
		catch {
			set fd [open $file r]
			set data [string trim [read $fd] "\n"]
			set lines [split $data "\n"]
			close $fd
		}

		set newfilecontents [list]

		set fileChanged 0
		set linebuf ""
		set verblinebuf ""
		foreach line $lines {
			set lineChanged 0

			append linebuf $line
			append verblinebuf "$line\n"
			if {[string index $line end] == "\\"} {
				set linebuf [string range $linebuf 0 end-1]

				continue
			}

			set lineinfo [_parseLine $linebuf]
			set linebuf ""

			foreach {ent vallist} $lineinfo {
				set linesvc [lindex $ent 0]

				if {$linesvc != $svc} {
					continue
				}

				set newvallist [list]
				set removedlist [list]
				foreach val $vallist {
					# Remove items that are exact matches
					if {[lsearch -exact $networks $val] != -1} {
						set lineChanged 1

						continue
					}

					# Remove items that are entirely a subset of what has been specified
					if {[_isIP $val]} {
						set itemFound 0
						foreach network $networks {
							if {![_isIP $network]} {
								continue
							}

							set network [::ip::normalize $network]

							set reduced [::ip::reduceToAggregates [list $val $network]]
							if {$reduced == [list $network] || $reduced == [list ${network}/32]} {
								set itemFound 1

								break
							}
						}

						if {$itemFound} {
							set lineChanged 1

							lappend removedlist $val

							continue
						}
					}

					lappend newvallist $val
				}
			}

			set linebuf ""
			if {!$lineChanged} {
				lappend newfilecontents [string range $verblinebuf 0 end-1]
				set verblinebuf ""

				continue
			}
			set verblinebuf ""

			set fileChanged 1

			foreach {ent vallist} $lineinfo {
				set linesvc [lindex $ent 0]
				set opts [lindex $ent 1]
				set result [lindex $ent 2]

				set appendlist [list $opts]
				if {$result != ""} {
					lappend appendlist $result
				}
				set appendbuf [string trim [join $appendlist {: }]]
				if {$appendbuf != ""} {
					set appendbuf " :${appendbuf}"
				}

				if {$linesvc != $svc} {
					set vallist [_normalizeHosts $vallist]
					lappend newfilecontents "$linesvc: $vallist${appendbuf}"
				} else {
					if {$comment} {
						set removedlist [_normalizeHosts $removedlist]
						lappend newfilecontents "# $linesvc: $removedlist${appendbuf}"
					}

					if {[llength $newvallist] != 0} {
						set newvallist [_normalizeHosts $newvallist]

						lappend newfilecontents "$linesvc: $newvallist${appendbuf}"
					}
				}
			}
		}

		if {!$fileChanged} {
			return 1
		}

		set backupfile "${file}.bak.[clock seconds]"
		if {[catch {
			file copy -force -- "$file" "$backupfile"
		} err]} {
			return -code error "Unable to create backup file ($backupfile): $err"
		}

		if {[catch {
			set fd [open $file w]
			puts $fd [join $newfilecontents "\n"]
			close $fd
		} err]} {
			file copy -force -- "$backupfile" "$file"

			return 0
		}

		return 1
	}

	proc _TEST {argv} {
		puts [join [summarize "hosts.allow"] "\n"]

		add "hosts.allow" sshd $argv
		remove "hosts.allow" sshd $argv
	}
}

package provide tcpwrappers 0.1
