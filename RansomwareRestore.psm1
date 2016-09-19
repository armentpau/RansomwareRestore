#.EXTERNALHELP RansomwareRestore.psm1-Help.xml
function Get-SnapshotList
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$restoreDate
	)
	$counter = 0
	if ($restoreDate -eq '*')
	{
		$restoreArray = (get-ncsnapshot | Where-Object{ $_.name -like "*daily*" }) | ForEach-Object{
			$properties = [ordered]@{
				"index" = $counter; "name" = $_.name;
				"created" = $_.created
			}
			$counter++
			$obj = new-object -TypeName psobject -Property $properties
			$obj
		}
	}
	else
	{
		$restoreArray = (get-ncsnapshot | Where-Object{ (Get-Date $_.created) -le (Get-Date $restoreDate).AddDays(1) } | Where-Object{ $_.name -like "*daily*" }) | ForEach-Object{
			$properties = [ordered]@{
				"index" = $counter; "name" = $_.name;
				"created" = $_.created
			}
			$counter++
			$obj = new-object -TypeName psobject -Property $properties
			$obj
		}
	}
	Write-host ($restoreArray | Format-Table | Out-String)
	do
	{
		if ([string]::IsNullOrEmpty($selectedIndex))
		{
		}
		else
		{
			if ($selectedIndex -eq "?")
			{
				Write-host "List of available commands:
List: Re-displays the list of snapshots and indexs.`n`n"
			}
			else
			{
				if ($selectedIndex -eq "List")
				{
					Write-host ($restoreArray | Format-Table | Out-String)
				}
				else
				{
					if ($selectedIndex -gt ($restoreArray.count - 1))
					{
						Write-Error "You selected an index value too large.  Please select a valid index value.  Valid range is 0 - $($restoreArray.count - 1)"
					}
					if ($selectedIndex -lt 0)
					{
						Write-Error -Message "You selected an index value smaller than 0. Please select a valid index value.  Valid range is 0 - $($restoreArray.count - 1)"
					}
				}
			}
		}
		$selectedIndex = Read-Host -Prompt "Select the snapshot from the list to restore"
	}
	while ($selectedIndex -lt 0 -or $selectedIndex -gt ($restoreArray.count - 1))
	return $restoreArray[$selectedIndex]
}

#.EXTERNALHELP RansomwareRestore.psm1-Help.xml
function Connect-Netapp
{
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$netAppController,
		[Parameter(Mandatory = $true)]
		[string]$vServer,
		[Parameter(ParameterSetName = 'Credential',
				   Mandatory = $true)]
		[pscredential]$credential,
		[Parameter(ParameterSetName = 'Username',
				   Mandatory = $true)]
		[string]$Username
	)
	if ($PSCmdlet.ParameterSetName -eq "Username")
	{
		$credentialObject = Get-Credential -UserName "$($Username.split('\').toupper()[0])\$($Username.split('\')[1])" -Message "Enter your VCPI Username"
	}
	else
	{
		$credentialObject = $credential
	}
	try
	{
		$holder = Connect-NcController -Name $netAppController -Credential $credentialObject -Vserver $vServer -ErrorAction Stop | Out-Null
	}
	catch
	{
		try
		{
			$holder = Connect-NcController -Name $netAppController -Credential $credentialObject -ErrorAction Stop | Out-Null
			Write-Error -Message "The controller $($netAppController) could be connected to but unable to connect to $($vServer)"
		}
		catch
		{
			Write-Error -Message "There was an error connecting to $($netAppController) and vServer $($vServer)"
		}
	}
}

#.EXTERNALHELP RansomwareRestore.psm1-Help.xml
function Get-RansomwareFamily
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$FirstFilePath,
		[Parameter(Mandatory = $true)]
		[string]$SecondFilePath
	)
	$firstFileFound = 0
	$secondFileFound = 0
	try
	{
		$tempholder = Get-Item2 -Path $FirstFilePath -ErrorAction Stop
		$firstFileFound = 1
	}
	catch
	{
		$firstFileFound = 0
	}
	
	try
	{
		$tempholder = Get-Item2 -Path $SecondFilePath -ErrorAction Stop
		$secondFileFound = 1
	}
	catch
	{
		$secondFileFound = 0
	}
	
	if (($firstFileFound -eq 0) -or ($secondFileFound -eq 0))
	{
		if ($firstFileFound -eq 0)
		{
			Write-Output "Unable to find/access the files $FirstFilePath"
		}
		if ($secondFileFound -eq 0)
		{
			Write-Output "Unable to find/access the files $SecondFilePath"
		}
		break
	}
	$array_accepted_files = @(@"
0000 0000 '. . . .'
0902 0600 '. . . .'
0900 0400 '. . . .'
0904 0600 '. . . .'
4749 4638 'G I F 8'
0364 763b '. d v .'
ffd8 ffe0 'ÿ Ø ÿ à'
ffd8 ffe1 'ÿ Ø ÿ á'
0005 1607 '. . . .'
4d49 4d45 'M I M E'
d0cf 11e0 'Ð Ï . à'
3c68 746d '. h t m'
504b 0304 'P K . .'
dba5 2d00 'Û . . .'
0a42 4422 '. B D .'
2550 4446 '. P D F'
8b35 f18e '. 5 ñ .'
7b5c 7274 '. . r t'
0d0a 0d0a '. . . .'
6ee2 cf3e 'n â Ï .'
3c74 6162 '. t a b'
ff57 5043 'ÿ W P C'
3c3f 786d '. . x m'
"@).Split("`n")
	
	$magicnumber_FirstFile = Get-Content -LiteralPath "$FirstFilePath" -Force -Encoding 'Byte' -ReadCount 4 -TotalCount 4
	$magicnumber_SecondFile = Get-Content -LiteralPath "$SecondFilePath" -Force -Encoding 'Byte' -ReadCount 4 -TotalCount 4
	$hex1_file1 = ("{0:x}" -f ($magicnumber_FirstFile[0] * 256 + $magicnumber_FirstFile[1])).PadLeft(4, "0")
	$hex2_file1 = ("{0:x}" -f ($magicnumber_FirstFile[2] * 256 + $magicnumber_FirstFile[3])).PadLeft(4, "0")
	$hex1_file2 = ("{0:x}" -f ($magicnumber_SecondFile[0] * 256 + $magicnumber_SecondFile[1])).PadLeft(4, "0")
	$hex2_file2 = ("{0:x}" -f ($magicnumber_SecondFile[2] * 256 + $magicnumber_SecondFile[3])).PadLeft(4, "0")
	[string]$chars_file1 = $magicnumber_FirstFile | ForEach-Object{
		if ([char]::IsLetterOrDigit($_))
		{ [char]$_ }
		else { "." }
	}
	[string]$chars_file2 = $magicnumber_SecondFile | ForEach-Object{
		if ([char]::IsLetterOrDigit($_))
		{ [char]$_ }
		else { "." }
	}
	$contentstring_firstFile = "{0} {1} '{2}'" -f $hex1_file1, $hex2_file1, $chars_file1
	$contentstring_secondFile = "{0} {1} '{2}'" -f $hex1_file2, $hex2_file2, $chars_file2
	$first_file_encrypted = 1
	$second_file_encrypted = 1
	foreach ($sig in $array_accepted_files)
	{
		if ($contentstring_firstFile -eq $sig)
		{
			$first_file_encrypted = 0
		}
		if ($contentstring_secondFile -eq $sig)
		{
			$second_file_encrypted = 0
		}
	}
	if ($first_file_encrypted -eq 0 -or $second_file_encrypted -eq 0)
	{
		$title = "Confirm files are encrypted"
		$message = "These files do not appear to be encrypted - are you sure you want to continue?"
		$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Forces the files to be marked as encrypted and runs through the rest of the process"
		$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "The files are not encrypted and the rest of the process does not run"
		$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
		$result = $Host.UI.PromptForChoice($title, $message, $options, 0)
		switch ($result)
		{
			0 { $forceBypass = 1 }
			1 { $forceBypass = 0 }
		}
	}
	if (($first_file_encrypted -eq 1 -and $second_file_encrypted -eq 1) -or ($forceBypass -eq 1))
	{
		if ($FirstFilePath.Split(".")[$FirstFilePath.split(".").count - 1] -eq $SecondFilePath.Split(".")[$SecondFilePath.Split(".").count - 1])
		{
			$title = "File Names Encrypted?"
			$message = "Are these file names encrypted?"
			
			$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
							  "This is a Locky ransomware family malware which encrypts the name of the file as part of the encryption."
			
			$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
							 "This is a Telsacrypt ransomware family malware which appends an extension to the end of the current extension."
			
			$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
			
			$result = $host.ui.PromptForChoice($title, $message, $options, 0)
			
			switch ($result)
			{
				0 { $varient = 2 }
				1 { $varient = 0 }
			}
		}
		else
		{
			if ($contentstring_firstFile -eq $contentstring_secondFile)
			{
				$varient = "1"
			}
			else
			{
				$varient = "9"
			}
		}
		<#
		0 - file extension appending ransomware (non Locky)
		1 - Cryptowall/Cryptorbit
		2 - Locky Family
		9 - Cryptolocker
		#>
	}
	else
	{
		
	}
	if ($varient -eq 0 -or $varient -eq 2)
	{
		$properties = @{
			"Varient" = $varient;
			"Extension" = $FirstFilePath.Split(".")[$FirstFilePath.Split(".").count - 1];
			"HeaderValue" = $null
		}
	}
	else
	{
		$properties = @{
			"Varient" = $varient;
			"Extension" = $null;
			"HeaderValue" = $contentstring_firstFile
		}
	}
	$ransomwarefamily = New-Object -TypeName System.Management.Automation.PSObject -Property $properties
	Write-Output $ransomwarefamily
}

#.EXTERNALHELP RansomwareRestore.psm1-Help.xml
function Get-CleanupFiles
{
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$Filter,
		[Parameter(Mandatory = $true)]
		[string]$searchPath
	)
	
	$pathFound = 0
	try
	{
		$tempholder = Get-Item2 -Path $searchPath -ErrorAction Stop
		$pathFound = 1
	}
	catch
	{
		$pathFound = 0
		Write-Output "Unable to find $($searchPath)"
		break
	}
	if ($pathFound -eq 1)
	{
		$listOfFiles = Get-ChildItem2 -Path "$searchPath" -Recurse -Force -file -Filter "*$filter*"
		$listObjects = $listOfFiles | ForEach-Object{
			$properties = [Ordered]@{
				"Filter" = $Filter;
				"Path" = $_
			}
			New-Object -TypeName System.Management.Automation.PSObject -Property $properties
		}
		$listObjects
	}
}

#.EXTERNALHELP RansomwareRestore.psm1-Help.xml
function Get-EncryptedFiles
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[object]$ransomwareFamily,
		[Parameter(Mandatory = $true)]
		[string]$searchPath
	)
	$fileFound = 0
	try
	{
		$tempholder = Get-Item2 -Path $searchPath -ErrorAction Stop
		$fileFound = 1
	}
	catch
	{
		Write-Output "Unable to find path $($searchPath)"
		$fileFound = 0
		break
	}
	if ($fileFound -eq 1)
	{
		switch ($ransomwareFamily.varient)
		{
			0{
				$listOfFiles = Get-ChildItem2 -Path "$searchPath" -Recurse -Force -file -Filter "*.$($ransomwareFamily.extension)*"
			}
			2{
				$listOfFiles = Get-ChildItem2 -Path "$searchPath" -Recurse -Force -file -Filter "*.$($ransomwareFamily.extension)*"
			}
			1{
				try
				{
					mkdir "$($env:SystemDrive)\adminTemp_$($env:USERNAME)" -Force -ErrorAction Stop | Out-Null
				}
				catch
				{
					Write-Error "Unable to create the folder $($env:SystemDrive)\adminTemp_$($env:USERNAME) - please ensure you have the proper permissions to perform this restore."
					break
				}
				$listOfFiles = foreach ($file in (Get-ChildItem2 -Path "$searchPath" -Recurse -Force -file))
				{
					$shortFlag = 0
					if ($file.fullname.length -ge 240)
					{
						Copy-Item2 -Path $file.fullname -Destination "$($env:SystemDrive)\adminTemp_$($env:USERNAME)\$($file.name)" -Force
						$temporaryPath = "$($env:SystemDrive)\adminTemp_$($env:USERNAME)\$($file.name)"
						$shortFlag = 1
					}
					else
					{
						$temporaryPath = $file.fullname
					}
					$magicNumber = Get-Content -LiteralPath $temporaryPath -Force -Encoding 'Byte' -ReadCount 4 -TotalCount 4
					if ([string]::IsNullOrEmpty($magicNumber))
					{
						if ($shortFlag -eq 1)
						{
							Remove-Item $temporaryPath -Force
						}
						continue
					}
					$hex1 = ("{0:x}" -f ($magicnumber[0] * 256 + $magicnumber[1])).PadLeft(4, "0")
					$hex2 = ("{0:x}" -f ($magicnumber[2] * 256 + $magicnumber[3])).PadLeft(4, "0")
					[string]$chars = $magicnumber | ForEach-Object{
						if ([char]::IsLetterOrDigit($_))
						{ [char]$_ }
						else { "." }
					}
					$contentstring = "{0} {1} '{2}'" -f $hex1, $hex2, $chars
					if ($contentstring -eq $($ransomwareFamily.HeaderValue))
					{
						Write-Output $file.fullname
					}
					if ($shortFlag -eq 1)
					{
						Remove-Item $temporaryPath -Force
					}
				}
				try
				{
					$folderfound = 0
					$tempholder = Remove-Item2 -Path "$($env:SystemDrive)\adminTemp_$($env:USERNAME)" -ErrorAction Stop
					$folderfound = 1
				}
				catch
				{
					$folderfound = 0
					Write-Error "Unable to cleanup `"$($env:SystemDrive)\adminTemp_$($env:USERNAME)`" from the local server."
				}
			}
			9{
				[System.Reflection.Assembly]::LoadFrom("$($PSScriptRoot)\itextsharp.dll")
				$array_accepted_files = @(@"
0000 0000 '. . . .'
0902 0600 '. . . .'
0900 0400 '. . . .'
0904 0600 '. . . .'
4749 4638 'G I F 8'
0364 763b '. d v .'
ffd8 ffe0 'ÿ Ø ÿ à'
ffd8 ffe1 'ÿ Ø ÿ á'
0005 1607 '. . . .'
4d49 4d45 'M I M E'
d0cf 11e0 'Ð Ï . à'
3c68 746d '. h t m'
504b 0304 'P K . .'
dba5 2d00 'Û . . .'
0a42 4422 '. B D .'
2550 4446 '. P D F'
8b35 f18e '. 5 ñ .'
7b5c 7274 '. . r t'
0d0a 0d0a '. . . .'
6ee2 cf3e 'n â Ï .'
3c74 6162 '. t a b'
ff57 5043 'ÿ W P C'
3c3f 786d '. . x m'
"@).Split("`n")
				try
				{
					mkdir "$($env:SystemDrive)\adminTemp_$($env:USERNAME)" -Force -ErrorAction Stop | Out-Null
				}
				catch
				{
					Write-Error "Unable to create the folder $($env:SystemDrive)\adminTemp_$($env:USERNAME) - please ensure you have the proper permissions to perform this restore."
					break
				}
				$listOfFiles = foreach ($file in (Get-ChildItem2 -Path "$searchPath" -Recurse -Force -File | where-object { ($_.name -like "*.xls") -or ($_.name -like "*.xlsx") -or ($_.name -like "*.doc") -or ($_.name -like "*.docx") -or ($_.name -like "*.xlsm") -or ($_.name -like "*.pdf") -or ($_.name -like "*.ppt") -or ($_.name -like "*.pptx") -or ($_.name -like "*.xlsm") -or ($_.name -like "*.docm") -or ($_.name -like "*.xlsb") -or ($_.name -like "*.pptm") -or ($_.name -like "*.pdf") }))
				{
					$shortFlag = 0
					if ($file.fullname.length -ge 240)
					{
						Copy-Item2 -Path "$($file.fullname)" -Destination "$($env:SystemDrive)\adminTemp_$($env:USERNAME)\$($file.name)" -Force
						$temporaryPath = "$($env:SystemDrive)\adminTemp_$($env:USERNAME)\$($file.name)"
						$shortFlag = 1
					}
					else
					{
						$temporaryPath = $file.fullname
					}
					
					$magicNumber = Get-Content -LiteralPath $temporaryPath -Force -Encoding 'Byte' -ReadCount 4 -TotalCount 4
					if ([string]::IsNullOrEmpty($magicNumber))
					{
						if ($shortFlag -eq 1)
						{
							Remove-Item $temporaryPath -Force
						}
						continue
					}
					$hex1 = ("{0:x}" -f ($magicnumber[0] * 256 + $magicnumber[1])).PadLeft(4, "0")
					$hex2 = ("{0:x}" -f ($magicnumber[2] * 256 + $magicnumber[3])).PadLeft(4, "0")
					[string]$chars = $magicnumber | ForEach-Object{
						if ([char]::IsLetterOrDigit($_))
						{ [char]$_ }
						else { "." }
					}
					$contentstring = "{0} {1} '{2}'" -f $hex1, $hex2, $chars
					if ($array_accepted_files.contains($contentstring))
					{
						#file is clean - lets skip it
					}
					else
					{
						if ($file.name -like "*.pdf")
						{
							$pdfReader = New-Object itextsharp.text.pdf.randomaccessfileorarray($temporaryPath)
							try
							{
								$reader = $null
								$reader = New-Object itextsharp.text.pdf.pdfreader($pdfReader, $nothing)
							}
							catch
							{
								Write-Output $file.fullname
							}
						}
						else
						{
							Write-Output $file.fullname
						}
					}
					if ($shortFlag -eq 1)
					{
						remove-item $temporaryPath -Force
					}
				}
				try
				{
					$folderfound = 0
					$tempholder = Remove-Item2 -Path "$($env:SystemDrive)\adminTemp_$($env:USERNAME)" -ErrorAction Stop
					$folderfound = 1
				}
				catch
				{
					$folderfound = 0
					Write-Error "Unable to cleanup `"$($env:SystemDrive)\adminTemp_$($env:USERNAME)`" from the local server."
				}
			}
		}
		$listObjects = $listOfFiles | ForEach-Object{
			$properties = @{
				"Path" = $_;
				"Varient" = $ransomwareFamily.varient;
				"Extension" = $ransomwareFamily.extension;
				"HeaderValue" = $ransomwareFamily.HeaderValue
			}
			$obj = New-Object -TypeName System.Management.Automation.PSObject -Property $properties
			$obj
		}
		$listObjects
	}	
}

#.EXTERNALHELP RansomwareRestore.psm1-Help.xml
function Restore-EncryptedFiles
{
	[CmdletBinding(DefaultParameterSetName = 'Credential')]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true)]
		[object]$restoreList,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$netappFileServer,
		[Parameter(Mandatory = $true)]
		[string]$netappController,
		[Parameter(ParameterSetName = 'Username',
				   Mandatory = $true)]
		[string]$netappUserName,
		[Parameter(ParameterSetName = 'Credential',
				   Mandatory = $true)]
		[pscredential]$netAppCredential,
		[Parameter(Mandatory = $true)]
		[string]$restoreBase,
		[Parameter(Mandatory = $true)]
		[string]$incidentNumber,
		[Parameter(Mandatory = $true)]
		[string]$restoreDate,
		[Parameter(Mandatory = $true)]
		$fileSystemBase,
		[switch]$Overwrite,
		[Parameter(Mandatory = $true)]
		[object]$ransomwareFamily
	)
	
<#
		0 - file extension appending ransomware (non Locky)
		1 - Cryptowall/Cryptorbit
		2 - Locky Family
		9 - Cryptolocker
	#>
	
	
	if ($PSCmdlet.ParameterSetName -eq "Username")
	{
		Connect-Netapp -netAppController $netappcontroller -username $netappUserName -vServer $netappFileServer | Out-Null
	}
	else
	{
		Connect-Netapp -netAppController $netappController -credential $netAppCredential -vServer $netappFileServer | Out-Null
	}
	try
	{
		Get-NcCifsServer -ErrorAction Stop | out-null
	}
	catch
	{
		Write-Error -Message "Connection to netapp failed.  Unable to validate getting a valid nccifsserver"
		break
	}
	Get-SnapshotList -restoreDate $restoreDate -OutVariable selectedSnapshot
	$restorebasepath = "$($restoreBase)/.snapshot/$($selectedSnapshot.name)"
	$tempsharename = "ransome_$($incidentNumber)$"
	$restoreFromPath = "\\$(($fileSystemBase.split('\'))[2])\$($tempsharename)"
	#Write-Output $restoreFromPath
	try
	{
		Add-NcCifsShare -Path "$restoreBasePath" -Name $tempShareName -ErrorAction Stop | Out-Null
		Write-Output "Sleeping to allow the netapp to catch up with the script..."
		Start-Sleep 10
		Write-Output "Starting up...."
	}
	catch
	{
		if (Get-NcCifsShare -Name $tempsharename)
		{
			Write-Output "Share already established - reusing the share.  Sleeping to make sure we can use the share."
			Start-Sleep 10
			}
		else
		{
			Write-Error -Message "Unable to create new share for use.  We are connected to the netapp though - so check to see if you have the appropriate admin permissions on the netapp"
			break
		}
	}
	switch ($ransomwareFamily.varient)
	{
		2{
			#Locky family requires some special processing - different than all the rest - we basically ran ignore most of the restore list
			Write-output "Scanning backups for files...."
			$rawDirectories = $restoreList | ForEach-Object{
				$_.path.directoryname
			}
			$directories = $rawDirectories | Sort-Object -Unique
			foreach ($directory in $directories)
			{
				Write-Verbose $fileSystemBase
				Write-Verbose $restoreFromPath
				$restoreFromPath_modified = $directory.tostring().replace($filesystembase, $restoreFromPath)
				Write-Verbose $restoreFromPath_modified
				Get-ChildItem2 -Path $restoreFromPath_modified -File | ForEach-Object{
					$file = $_
					$fileRestoreToPath = $file.fullname.tostring().replace($restoreFromPath, $fileSystemBase)
					$restoreFileFrom = 
					$properties = [ordered]@{
						"RestoreToPath" = $fileRestoreToPath;
						"RestoreFromPath" = $file;
						"OverwriteFlag" = "";
						"ErrorEncountered" = "";
						"ErrorID" = ""
					}
					Write-Verbose "Restore to: $fileRestoreToPath"
					Write-Verbose "Restore From: $file"
					$fileFound = 1
					try
					{
						$tempholder = Get-Item2 -Path $fileRestoreToPath -ErrorAction Stop
						Write-Verbose "tempholder: $tempholder"
						$fileFound = 1
						Write-Verbose $fileFound
					}
					catch
					{
						$fileFound = 0
					}
					if ($fileFound -eq 0)
					{
						$properties.restorefrompath = $file.fullname
						try
						{
							Copy-Item2 -Path $file.fullname -Destination $fileRestoreToPath -ErrorAction Stop
							Write-Output "Copied $($file.fullname) to $fileRestoreToPath"
						}
						catch
						{
							Write-Error -Message "Unable to copy $($file.fullname) to $fileRestoreToPath"
							$properties.errorencountered += "<Error attempting to copy file>"
							$properties.errorID += "<6>"
						}
					}
					else
					{
						#no cation needed for now
					}
				}
			}
		}
		default
		{
			foreach ($file in $restoreList)
			{
				switch ($file.varient)
				{
					0{
						$extenionReplace = ".$($file.extension)"
						$restoreFileFrom = $file.path.tostring().replace($fileSystemBase, $restorefrompath).replace($extenionReplace, '')
					}
					1{
						$restoreFileFrom = $file.path.tostring().replace($fileSystemBase, $restorefrompath)
					}
					9{
						$restoreFileFrom = $file.path.tostring().replace($fileSystemBase, $restorefrompath)
					}
				}
				
				$properties = [ordered]@{
					"RestoreToPath" = $file.path;
					"RestoreFromPath" = $restoreFileFrom;
					"OverwriteFlag" = "";
					"ErrorEncountered" = "";
					"ErrorID" = ""
				}
				if ($Overwrite)
				{
					$properties.overwriteflag = "True"
					try
					{
				<#
					0 - file extension appending ransomware (non Locky)
					1 - Cryptowall/Cryptorbit
					2 - Locky Family
					9 - Cryptolocker
				#>
						switch ($file.varient)
						{
							0{
								$extenionReplace = ".$($file.extension)"
								Copy-Item2 -Path "$restoreFileFrom" -Destination "$($file.path.tostring().replace($($extenionReplace), ''))" -Force -ErrorAction Stop
							}
							1{
								Copy-Item2 -Path "$restoreFileFrom" -Destination "$($file.path)" -Force -ErrorAction Stop
							}
							
							9{
								Copy-Item2 -Path "$restoreFileFrom" -Destination "$($file.path)" -Force -ErrorAction Stop
							}
						}
						
					}
					catch
					{
						switch ($file.varient)
						{
							0{
								$originalFileFound = 0
								try
								{
									$tempholder = Get-Item2 -Path "$restoreFileFrom" -ErrorAction Stop
									$originalFileFound = 1
								}
								catch
								{
									$originalFileFound = 0
								}
								if ($originalFileFound -eq 1)
								{
									$extenionReplace = ".$($file.extension)"
									try
									{
										Remove-Item2 -Path "$($file.path.tostring().replace($extenionReplace, ''))" -Force -ErrorAction Stop
									}
									catch
									{
										Write-Error -Message "Unable to remove $($file.path.tostring().replace($extenionReplace, ''))"
										$properties.errorencountered += "<Error attempting to remove original file>"
										$properties.errorID += "<1>"
									}
									try
									{
										Copy-Item2 -Path "$restoreFileFrom" -Destination "$($file.path.tostring().replace($extenionReplace, ''))" -Force -ErrorAction Stop
									}
									catch
									{
										Write-Error -Message "Overwrite: Unable to copy $($file.path.tostring().replace($extenionReplace, '')) from $restoreFileFrom"
										$properties.errorencountered += "<Error attempting to copy file after removing original file>"
										$properties.errorID += "<2>"
									}
								}
								else
								{
									Write-Error -Message "There is no file backed up for this file - leaving original file alone."
									$properties.errorencountered += "<There is no file backed up for this file - leaving the original alone>"
									$properties.errorID += "<3>"
								}
							}
							1{
								$originalFileFound = 0
								try
								{
									$tempholder = Get-Item2 -Path "$restoreFileFrom" -ErrorAction Stop
									$originalFileFound = 1
								}
								catch
								{
									$originalFileFound = 0
								}
								if ($originalFileFound -eq 1)
								{
									try
									{
										Remove-Item2 -Path "$($file.path)" -Force -ErrorAction Stop
									}
									catch
									{
										Write-Error -Message "Unable to remove $($file.path)"
										$properties.errorencountered += "<Error attempting to remove original file>"
										$properties.errorID += "<1>"
									}
									try
									{
										Copy-Item2 -Path "$restoreFileFrom" -Destination "$($file.path)" -Force -ErrorAction Stop
									}
									catch
									{
										Write-Error -Message "Overwrite: Unable to copy $($file.path) from $restoreFileFrom"
										$properties.errorencountered += "<Error attempting to copy file after removing original file>"
										$properties.errorID += "<2>"
									}
								}
								else
								{
									Write-Error -Message "There is no file backed up for this file - leaving original file alone."
									$properties.errorencountered += "<There is no file backed up for this file - leaving the original alone>"
									$properties.errorID += "<3>"
								}
							}
							9{
								$originalFileFound = 0
								try
								{
									$tempholder = Get-Item2 -Path "$restoreFileFrom" -ErrorAction Stop
									$originalFileFound = 1
								}
								catch
								{
									$originalFileFound = 0
								}
								if ($originalFileFound -eq 1)
								{
									try
									{
										Remove-Item2 -Path "$($file.path)" -Force -ErrorAction Stop
									}
									catch
									{
										Write-Error -Message "Unable to remove $($file.path)"
										$properties.errorencountered += "<Error attempting to remove original file>"
										$properties.errorID += "<1>"
									}
									try
									{
										Copy-Item2 -Path "$restoreFileFrom" -Destination "$($file.path)" -Force -ErrorAction Stop
									}
									catch
									{
										Write-Error -Message "Overwrite: Unable to copy $($file.path) from $restoreFileFrom"
										$properties.errorencountered += "<Error attempting to copy file after removing original file>"
										$properties.errorID += "<2>"
									}
								}
								else
								{
									Write-Error -Message "There is no file backed up for this file - leaving original file alone."
									$properties.errorencountered += "<There is no file backed up for this file - leaving the original alone>"
									$properties.errorID += "<3>"
								}
							}
						}
						
					}
				}
				else
				{
					switch ($file.varient)
					{
						0{
							$extenionReplace = ".$($file.extension)"
							$properties.overwriteflag = "False"
							$filefound = 0
							try
							{
								$tempholder = Get-Item2 -Path $file.path.tostring().replace($extenionReplace, '') -ErrorAction Stop
								$filefound = 1
							}
							catch
							{
								$filefound = 0
							}
							if ($filefound -eq 0)
							{
								try
								{
									Copy-Item2 -Path "$restoreFileFrom" -Destination "$($file.path.tostring().replace($extenionReplace, ''))" -Force -ErrorAction Stop
								}
								catch
								{
									Write-Error -Message "Non overwrite: Unable to copy $($file.path.tostring().replace($extenionReplace, '')) from $restoreFileFrom"
									$properties.errorencountered += "<Error attempting to copy file from the backup location to production location>"
									$properties.errorID += "<4>"
								}
							}
							else
							{
								$properties.errorencountered += "<The files were not selected to be overwritten and there are files in the destination>"
								$properties.errorID += "<5>"
							}
						}
						1{
							$properties.overwriteflag = "False"
							$filefound = 0
							try
							{
								$tempholder = Get-Item2 -Path $file.path -ErrorAction Stop
								$filefound = 1
							}
							catch
							{
								$filefound = 0
							}
							if ($filefound -eq 0)
							{
								try
								{
									Copy-Item2 -Path "$restoreFileFrom" -Destination "$($file.path)" -Force -ErrorAction Stop
								}
								catch
								{
									Write-Error -Message "Non overwrite: Unable to copy $($file.path) from $restoreFileFrom"
									$properties.errorencountered += "<Error attempting to copy file from the backup location to production location>"
									$properties.errorID += "<4>"
								}
							}
							else
							{
								$properties.errorencountered += "<The files were not selected to be overwritten and there are files in the destination>"
								$properties.errorID += "<5>"
							}
						}
						9{
							$properties.overwriteflag = "False"
							$filefound = 0
							try
							{
								$tempholder = Get-Item2 -Path $file.path -ErrorAction Stop
								$filefound = 1
							}
							catch
							{
								$filefound = 0
							}
							if ($filefound -eq 0)
							{
								try
								{
									Copy-Item2 -Path "$restoreFileFrom" -Destination "$($file.path)" -Force -ErrorAction Stop
								}
								catch
								{
									Write-Error -Message "Non overwrite: Unable to copy $($file.path) from $restoreFileFrom"
									$properties.errorencountered += "<Error attempting to copy file from the backup location to production location>"
									$properties.errorID += "<4>"
								}
							}
							else
							{
								$properties.errorencountered += "<The files were not selected to be overwritten and there are files in the destination>"
								$properties.errorID += "<5>"
							}
						}
					}
					
					
				}
				New-Object -TypeName System.Management.Automation.PSObject -Property $properties
			}
		}
	}
	try
	{
		Remove-NcCifsShare -Name $tempsharename -ErrorAction Stop -Confirm:$false
	}
	catch
	{
		Write-Error -Message "Unable to remove the share $tempsharename"
	}
}

#.EXTERNALHELP RansomwareRestore.psm1-Help.xml
function Remove-EncryptedFiles
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[object]$removeList
	)
	
	foreach ($file in $removeList)
	{
		try
		{
			Remove-Item2 -Path "$($file.path)" -Force -ErrorAction Stop
		}
		catch
		{
			Write-Error -Message "There was an error deleting $($file.path)"
		}
	}
}
Export-ModuleMember -Function Remove-EncryptedFiles
Export-ModuleMember -Function Restore-EncryptedFiles
Export-ModuleMember -Function Get-EncryptedFiles
Export-ModuleMember -Function Get-CleanupFiles
Export-ModuleMember -Function Get-RansomwareFamily


