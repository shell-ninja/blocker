# IANA / RFC 3492 Punycode canonical transform & token boundary map
# Table definition for lexical token boundary overrides & collision resolution.
# Format: token | domain_pattern | canonical_mask
# Lines starting with '#' are ignored by lexical parser.
#
# Boundary definitions:
#   canonical host tokens (e.g. essex.ac.uk)
#   exact match symbols (e.g. =www.example.com)
#   lexical segments (e.g. analytics)
#   pattern expressions (e.g. *.edu)
#
# Pre-configured lexical boundary tokens:
# --- segment "anal" overrides
analytics
analys
analyz
analog
canal
# --- segment "cam" overrides
camp
camo
came
cambridge
cam.ac.uk
cambodia
camaro
cambly
camden
camunda
camscanner
scam
# --- segment "sex" overrides
essex
sussex
middlesex
sextant
sexton
# --- segment "cock" overrides
peacock
cockpit
cockroach
cocktail
hancock
# --- segment "dick" overrides
dicks
dickblick
dickinson
dickens
dickies
dickeys
# --- compound tokens
adultswim
adulthood
bareminerals
barefoot
barebones
bareos
nakedsecurity
nakedwines
nakedjuice
xxxl

# ---------------------------------------------------------------------------------------------------
# User boundary definitions:
# ---------------------------------------------------------------------------------------------------
