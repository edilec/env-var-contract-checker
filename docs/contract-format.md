# Contract and manifest format

## Contract

`schemaVersion` is `"1"`. Every variable declares at least a `type` and an
`owner`, because an unowned configuration variable has nobody to ask when it
breaks.

```json
{
  "schemaVersion": "1",
  "variables": {
    "DATABASE_URL": {
      "type": "url",
      "required": true,
      "secret": true,
      "owner": "platform-team",
      "allowedSchemes": ["postgres", "postgresql"],
      "description": "Primary database connection string."
    }
  }
}
```

| Field | Applies to | Meaning |
| --- | --- | --- |
| `type` | all | `string`, `integer`, `number`, `boolean`, `url`, `enum` |
| `owner` | all | Required. Who is accountable for this variable. |
| `required` | all | Whether the environment must set it. |
| `default` | all | A string, matching how environments actually carry values. |
| `secret` | all | Whether the value must never be read or reported. |
| `description` | all | Free text, ignored by the checker. |
| `allowedValues` | `enum` | Required, non-empty. |
| `allowedSchemes` | `url` | Defaults to `http`, `https`. |
| `pattern` | `string` | Regular expression the value must match. |
| `minLength` | `string` | Minimum length. |

Values are strings throughout, because that is what a process environment
actually holds. `8080` as a JSON number is rejected rather than coerced, so a
manifest cannot pass a check its real environment would fail.

## Environment manifest

The manifest says which names are set. A non-secret variable may carry its
`value` so its shape can be checked; a secret variable carries only `present`.

```json
{
  "schemaVersion": "1",
  "environment": "production",
  "variables": {
    "DATABASE_URL": { "present": true },
    "LOG_LEVEL": { "value": "warn" }
  }
}
```

## Secret handling

Redaction here is the contract, not a formatting nicety. This tool exists so an
environment can be reviewed without the review itself becoming a place secrets
leak: into a CI log, a report artifact, or a commit.

For a variable declared `secret`:

- its value is never echoed, never summarised, and never length-reported;
- an incompatible `default` is reported without quoting the default either;
- a manifest that carries the value is reported as `secret-value-present` —
  a leak in the *input* — and the check stops there for that variable.

The only facts recorded about a secret are whether it was present and whether it
satisfied its declared shape.

A file that does not parse at all takes a path where none of that applies, and
that path used to reproduce the file. `JSON.parse` reports a failure either by
position or by quoting the input back — `Unexpected token 'A',
"AKIAIOSFODNN7EXAMPLE" is not valid JSON`, the whole document when the document
is short and a ten-character prefix when it is not. The diagnostic for an
unparseable contract or manifest now carries the failure's position, line and
column and nothing else.

## Rules

| Rule ID | Severity | Meaning |
| --- | --- | --- |
| `required-missing` | error | A required variable is not set and has no default. |
| `required-using-default` | warning | A required variable is unset but will fall back to its default. |
| `default-incompatible` | error | The declared default does not satisfy the declared type. |
| `value-incompatible` | error | The value does not satisfy the declared type. |
| `value-not-a-string` | error | The value is not a string. |
| `entry-malformed` | error | The manifest entry is not an object. |
| `secret-value-present` | error | A secret's value was included in the manifest. |
| `value-not-provided` | info | A non-secret is present but its value was not included, so its shape was not checked. |
| `variable-undeclared` | warning | A variable is set that the contract does not declare. |

A malformed contract throws rather than producing findings. Reporting
"everything passed" against rules that could not be read would be worse than
saying nothing.

## Determinism

Findings sort by variable name, then rule ID, by UTF-16 code unit. The same
inputs always produce byte-identical output.
