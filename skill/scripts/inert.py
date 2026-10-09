"""Shared code-point policy for inert text rendering.

Kept outside ``scripts.tools`` so the driver can use the same policy without
importing the adapter registry. The set covers C0, DEL/C1, the Unicode line and
paragraph separators, and the bidi controls named by #2118 item 1 / #2712.
"""


INERT_ESCAPE_CODE_POINTS = frozenset(
    (*range(0x0000, 0x0020),
     0x007F,
     *range(0x0080, 0x00A0),
     0x061C,
     0x200E, 0x200F,
     0x2028, 0x2029,
     *range(0x202A, 0x202F),
     *range(0x2066, 0x206A))
)
