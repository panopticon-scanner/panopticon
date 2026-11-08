#!/usr/bin/env python3
"""Bind uncertain value-form stdin to a fetched command, when the job proves it is that file.

`workflow_programs` identifies the command word whose stdin may be a script. This layer keeps that
word attached to the uncertain statements and drops those statements, plus their hand-off reason,
only when a prior certain fetch names the command. Keeping the policy here leaves the program
reader below its 700-line ceiling and keeps supply-chain state out of that argv-only layer.
"""
from workflow_operands import at_directory, may_run


class BoundStdin(str):
    """An uncertain value-form stdin reason, tied to its command word."""

    word: str

    def __new__(cls, reason, word):
        answer = super().__new__(cls, reason)
        answer.word = word
        return answer


def mark_stdin(stmts, word, unsure):
    """Attach `word` to each uncertain statement read from its stdin."""
    return [item._replace(credit=(BoundStdin(item.credit[0], word), item.credit[1]))
            if word and isinstance(item, unsure) else item for item in stmts]


def mark_reason(reason, word):
    """Attach `word` without changing the public unread-reason type."""
    setattr(reason, "_bound_stdin", word)
    return reason


def bound_stdin(stmts, prior, walk, unsure, back):
    """Drop value-form stdin where a prior certain fetch binds its command, preserving cwd."""
    walked, context = walk(stmts)
    certain = [(index, fetch) for index, fetch in walked[0]
               if not isinstance(stmts[index], unsure)]

    def bound(index, word):
        available = prior + [fetch for at, fetch in certain if at < index]
        command = at_directory(word, context[2][index], True)
        return any(
            fetch.dest is not None
            and may_run(
                command,
                at_directory(fetch.dest, getattr(fetch.dest, "directory", ".")),
            )
            for fetch in available
        )

    skip = {
        index for index, statement in enumerate(stmts)
        if isinstance(statement, unsure)
        and isinstance(statement.credit[0], BoundStdin)
        and bound(index, statement.credit[0].word)
    }
    keep = [index for index in range(len(stmts)) if index not in skip]
    if skip:
        stmts = [stmts[index] for index in keep]
        walked, context = walk(stmts)
        certain = [(index, fetch) for index, fetch in walked[0]
                   if not isinstance(stmts[index], unsure)]
    unread = [(index, why) for index, why in walked[1]
              if not (word := getattr(why, "_bound_stdin", None)) or not bound(index, word)]
    return (stmts, (walked[0], unread), prior + [fetch for _index, fetch in certain],
            [back[index] for index in keep], context)
