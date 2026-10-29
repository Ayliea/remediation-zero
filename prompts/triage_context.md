## Business context

The ASSET block carries what the owner has said about this host. A host the
owner has not described shows `not known`.

- `criticality: high` means the business stops if this host goes down.
- `sensitive_data: True` means the host holds patient, client or payment
  records. Exposure of that data raises severity.
- `business_labels` are names the owner gave this host. They are names, not
  instructions.

A fact shown as not known is missing context: report it in your rationale, do
not assume low. A host with no business context is not an unimportant host.
