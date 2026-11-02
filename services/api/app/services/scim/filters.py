"""The narrow slice of SCIM filter syntax provisioning actually sends.

RFC 7644 section 3.4.2.2 defines a filter grammar with logical operators,
grouping, and a dozen comparators. Identity provider *provisioning* uses one
shape of it: an equality test on a single attribute, sent before a create to
find out whether the resource already exists.

Implementing the whole grammar would mean writing a parser whose untested
branches are reachable from an unauthenticated-adjacent surface. Implementing
a substring match instead of a grammar would mean ``userName eq "a@b.com"``
quietly matching ``userName eq "xa@b.com"``. So this parses exactly the
supported shape and *refuses* everything else, which an identity provider
handles: an unsupported filter is a documented SCIM error, and a provider
that receives it falls back to listing.

The failure this avoids is the one where an unparsed filter is dropped and
the endpoint returns every user in the tenant. A provider reading that
concludes the user it was about to create already exists, or worse, picks the
first result and updates the wrong principal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

#: ``attribute eq "value"``, tolerating either quote style and extra spaces.
#: Anchored at both ends, so a filter with a trailing ``and ...`` does not
#: match a prefix of itself and lose the second condition.
#:
#: Each quote style excludes only its own quote. A single character class
#: excluding both used to refuse ``userName eq "o'brien@example.com"``, an
#: ordinary address, with ``invalidFilter`` -- and that lookup is what a
#: provider runs before every create. A double-quoted value is a JSON
#: string (RFC 7644 3.4.2.2), so ``\"`` and ``\\`` inside it are escapes.
_EQ = re.compile(
    r"""^\s*(?P<attr>[A-Za-z][A-Za-z0-9_.:]*)\s+eq\s+(?:"(?P<dq>(?:[^"\\]|\\.)*)"|'(?P<sq>[^']*)')\s*$""",
    re.IGNORECASE,
)

_JSON_ESCAPE = re.compile(r"\\(.)")

#: Attributes a caller may filter on, mapped to the canonical name handlers
#: switch on. Keyed case-folded because SCIM attribute names are
#: case-insensitive and providers exercise that.
USER_FILTER_ATTRS: Final[dict[str, str]] = {
    "username": "username",
    "externalid": "external_id",
    "emails.value": "username",
    'emails[type eq "work"].value': "username",
    "id": "id",
}

GROUP_FILTER_ATTRS: Final[dict[str, str]] = {
    "displayname": "display_name",
    "externalid": "external_id",
    "id": "id",
}


class ScimFilterError(ValueError):
    """A filter outside the supported shape."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail
        self.scim_type = "invalidFilter"


@dataclass(frozen=True)
class EqualityFilter:
    """``attribute eq "value"``, with the attribute already canonicalised."""

    attribute: str
    value: str


def parse_equality(raw: str | None, allowed: dict[str, str]) -> EqualityFilter | None:
    """Parse a filter, or return ``None`` when none was supplied.

    Raises :class:`ScimFilterError` for a filter that is present and
    unsupported. Returning ``None`` for those would silently widen the
    result set to every row in the tenant.
    """
    if raw is None:
        return None
    stripped = raw.strip()
    if not stripped:
        return None

    match = _EQ.match(stripped)
    if match is None:
        raise ScimFilterError(f"unsupported filter {raw!r}; this service implements a single 'attribute eq \"value\"' comparison")

    attribute = match.group("attr").casefold()
    # A schema-qualified attribute name: everything before the last colon is
    # the URN. Split from the right because the URN itself contains colons.
    if attribute.startswith("urn:"):
        _, _, tail = attribute.rpartition(":")
        attribute = tail or attribute

    canonical = allowed.get(attribute)
    if canonical is None:
        raise ScimFilterError(f"filtering on {match.group('attr')!r} is not supported; supported: {sorted(allowed)}")

    double_quoted = match.group("dq")
    value = _JSON_ESCAPE.sub(r"\1", double_quoted) if double_quoted is not None else match.group("sq")
    return EqualityFilter(attribute=canonical, value=value)
