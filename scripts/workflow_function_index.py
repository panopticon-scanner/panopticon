#!/usr/bin/env python3
"""Source-order indexes used by workflow function-gating proofs.

The guard asks about a function once for each check in its body.  This index
keeps those questions on the definitions, calls, and posture changes that can
affect their answer instead of making each one scan the whole statement list.
"""
from bisect import bisect_right
from collections import defaultdict

from shell_reader import command


class ClosingIndex:
    """Closing runs shared by each statement's step-status question."""

    def __init__(self, stmts, is_closer):
        self.stmts = stmts
        self.closers = [is_closer(statement) for statement in stmts]
        self.ends = list(range(len(stmts)))
        for position in range(len(stmts) - 2, -1, -1):
            if (stmts[position].separator not in ("&", "&&", "||")
                    and self.closers[position + 1]):
                self.ends[position] = self.ends[position + 1]
        self.blocks: dict[int, tuple[object, list[int | None]]] = {}

    def run(self, position, fails):
        """End and first detached/uncredited pipeline closer after ``position``."""
        end = self.ends[position]
        if end == position:
            return end, None
        key, cached = id(fails), self.blocks.get(id(fails))
        if cached is None or cached[0] is not fails:
            next_blocks: list[int | None] = [None] * (len(self.closers) + 1)
            block = None
            for at in range(len(self.closers) - 1, -1, -1):
                statement = self.stmts[at]
                if (self.closers[at] and (statement.separator == "&"
                        or len(statement.stages) > 1 and not fails[at])):
                    block = at
                next_blocks[at] = block
            cached = fails, next_blocks
            self.blocks[key] = cached
        block = cached[1][position + 1]
        return end, block if block is not None and block <= end else None


class _PipelineFrame:
    """One structural group, resolved to an enclosing pipeline if it has one."""

    __slots__ = ("depth", "parent", "piped", "resolved", "resolved_depth")

    def __init__(self, parent):
        self.parent = parent
        self.depth = parent.depth + 1 if parent is not None else 1
        self.piped = None
        self.resolved = None
        self.resolved_depth = 0


class FunctionIndex:
    """Definitions, direct calls, barriers, and piped function-body groups."""

    def __init__(self, stmts, names, function_syntax, posture_barrier):
        definitions, calls = defaultdict(list), defaultdict(list)
        barriers, frames, piped_at, structural_depths = [], [], [], []
        unmatched: list[tuple[int, tuple[int, int] | None]] = []
        top, structural_depth = None, 0
        for index, statement in enumerate(stmts):
            defined = set()
            for position, stage in enumerate(statement.stages):
                name, braces = function_syntax(stage.argv)
                if name is not None:
                    defined.add(name)
                argv = command(stage.argv)
                if argv[:1] and argv[0] in names:
                    calls[argv[0]].append((index, position))
                opens = stage.group_open + braces.count("{")
                closes = stage.group_close + braces.count("}")
                structural_depth += opens - closes
                for _opening in range(opens):
                    top = _PipelineFrame(top)
                    frames.append(top)
                for _closing in range(closes):
                    piped = ((index, position + 1)
                             if position + 1 < len(statement.stages) else None)
                    if top is None:
                        if not unmatched or unmatched[-1][0] != index:
                            unmatched.append((index, piped))
                        continue
                    closed, top = top, top.parent
                    closed.piped = piped
            piped_at.append(top)
            structural_depths.append(structural_depth)
            for name in defined:
                definitions[name].append(index)
            if posture_barrier(statement, names):
                barriers.append(index)
        for frame in frames:
            if frame.piped is not None:
                frame.resolved = frame.piped
                frame.resolved_depth = frame.depth
            elif frame.parent is not None:
                frame.resolved = frame.parent.resolved
                frame.resolved_depth = frame.parent.resolved_depth
        self.definitions = definitions
        self.calls = calls
        self.barriers = barriers
        self.barrier_set = set(barriers)
        self.next_barriers: list[int | None] = [None] * (len(stmts) + 1)
        next_barrier = None
        for position in range(len(stmts) - 1, -1, -1):
            if position in self.barrier_set:
                next_barrier = position
            self.next_barriers[position] = next_barrier
        self.piped_at = piped_at
        self.structural_depths = structural_depths
        self.unmatched = unmatched
        self.unmatched_positions = [index for index, _piped in unmatched]
        self.off = (False,) * len(stmts)
        self.on = (True,) * len(stmts)

    def events(self, name, after):
        """Positions after ``after`` that redefine ``name`` or change posture."""
        definitions = self.definitions[name]
        at_definition = bisect_right(definitions, after)
        barrier = (self.next_barriers[after + 1]
                   if after + 1 < len(self.next_barriers) else None)
        while at_definition < len(definitions) or barrier is not None:
            definition = (definitions[at_definition]
                          if at_definition < len(definitions) else None)
            if barrier is None or definition is not None and definition < barrier:
                yield definition
                at_definition += 1
            elif definition is None or barrier < definition:
                yield barrier
                barrier = self.next_barriers[barrier + 1]
            else:
                yield definition
                at_definition += 1
                barrier = self.next_barriers[barrier + 1]

    def call_statements(self, name, after):
        """Statement indexes containing a direct call of ``name`` after a body."""
        sites = self.calls[name]
        at = bisect_right(sites, (after, 1 << 60))
        previous = None
        for statement, _position in sites[at:]:
            if statement != previous:
                yield statement
                previous = statement

    def changed_before(self, name, after, before):
        """Whether posture or this definition changed in ``(after, before)``."""
        definitions = self.definitions[name]
        barrier = (self.next_barriers[after + 1]
                   if after + 1 < len(self.next_barriers) else None)
        definition = bisect_right(definitions, after)
        return ((barrier is not None and barrier < before)
                or (definition < len(definitions) and definitions[definition] < before))

    def defines(self, name, position):
        """Whether ``position`` defines ``name``."""
        definitions = self.definitions[name]
        at = bisect_right(definitions, position - 1)
        return at < len(definitions) and definitions[at] == position

    def is_barrier(self, position):
        """Whether ``position`` may change function-call posture."""
        return position in self.barrier_set

    def piped_group(self, position):
        """Pipeline start for a structural group enclosing ``position``."""
        frame = self.piped_at[position] if position < len(self.piped_at) else None
        if frame is not None:
            # The legacy scan counts unmatched closers in its net depth.  It
            # still examines the first enclosing close, then stops as soon as
            # that depth is exhausted.  Keep the indexed answer within that
            # same number of live frames instead of climbing past the closer.
            remaining = max(1, self.structural_depths[position])
            shallowest = frame.depth - remaining + 1
            return frame.resolved if frame.resolved_depth >= shallowest else None
        at = bisect_right(self.unmatched_positions, position)
        return self.unmatched[at][1] if at < len(self.unmatched) else None

