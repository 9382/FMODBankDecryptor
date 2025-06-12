# FMODBankDecyptor

A tool to decrypt `.bank` files generated with an encryption key by FMOD Studio

Tested on FMOD Studio 2.03 bank files upwards of 160MB large

## Usage

This is a CLI tool and is therefore used as such

### Arguments
- `--key` - Regular string. Required to actually decrypt bank files
- `--output-folder` - If specified, all decrypted banks will be created in the given folder. Otherwise, decrpyted bank files will be made in the same folder as their original file with the `.decrypted.bank` extension
- `--guess` - Tries to provide a guess for what the encryption key might be for a bank file. Not guaranteed to be correct
- `--verbose` - Toggles extra debug information.

Input files and folders are specified after the named arguments. If a folder is provided, all files ending `.bank` (that aren't `.decrypted.bank`) in that folder will be used

### Examples
```
FMODBankDecyptor --key "enc_key" "folder/containing/banks"
FMODBankDecyptor --key "enc_key" --output-folder "some/folder" "folder/containing/banks" "specific/file.bank"
FMODBankDecyptor --guess "specific/file.bank"
```

## Building

Can be built using Visual Studio or `dotnet build`. Pretty basic project, no special prerequisites here, should work out of the box

## Disclaimer

This tool only provides the abilit to decrypt `.bank` files. It can not understand or extract their contents, nor can it decrypt something if you don't know the key.