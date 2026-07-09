package capability

import "github.com/sd-strax/reckon/identity"

// emailNormalizer handles OCSF email_activity (class_uid 4009) → STIX (§4.10):
// the email-message, every address (from/to/cc/bcc), attachment files, and body
// URLs, with a contains relationship from the message to each attachment and URL.
type emailNormalizer struct{ r *identity.Resolver }

func (*emailNormalizer) ClassUID() int { return 4009 }
func (*emailNormalizer) Version() int  { return 1 }

func (n *emailNormalizer) Normalize(evt OcsfEvent) (NormalizationResult, error) {
	p := evt.Payload
	b := newBuilder(n.r, evt, "email_activity", n.Version())

	from := pathStr(p, "email.from")
	fromRef := b.emailAddr(from)
	toRefs := b.emailAddrs("email.to")
	b.emailAddrs("email.cc")
	b.emailAddrs("email.bcc")

	subject := pathStr(p, "email.subject")
	msgUID := pathStr(p, "email.message_uid")
	msgID := b.addSCO(
		n.r.EmailMessage(msgUID, from, subject, evt.Time),
		identity.TypeEmailMessage,
		map[string]any{
			"message_id": msgUID,
			"subject":    subject,
			"from_ref":   string(fromRef),
			"to_refs":    stringifyRefs(toRefs),
		},
	)

	// Attachments (contains) and body URLs (contains).
	if atts, ok := lookupPath(p, "email.attachments"); ok {
		if arr, ok := atts.([]any); ok {
			for _, item := range arr {
				if m, ok := item.(map[string]any); ok {
					if fileID := b.addFileFromMap(m); fileID != "" {
						b.addRel(RelContains, msgID, fileID)
					}
				}
			}
		}
	}
	if urls, ok := lookupPath(p, "email.urls"); ok {
		if arr, ok := urls.([]any); ok {
			for _, item := range arr {
				if urlID := b.url(toString(item)); urlID != "" {
					b.addRel(RelContains, msgID, urlID)
				}
			}
		}
	}

	return b.finish(nil), nil
}

// emailURLNormalizer handles OCSF email_url_activity (class_uid 4011) → STIX
// (§4.11): the clicked URL, the clicker, the (possibly stub) email-message, and
// the host, with a clicked edge (user → url) and a contains edge (message → url).
type emailURLNormalizer struct{ r *identity.Resolver }

func (*emailURLNormalizer) ClassUID() int { return 4011 }
func (*emailURLNormalizer) Version() int  { return 1 }

func (n *emailURLNormalizer) Normalize(evt OcsfEvent) (NormalizationResult, error) {
	p := evt.Payload
	b := newBuilder(n.r, evt, "email_url_activity", n.Version())

	urlID := b.url(pathStr(p, "url.url_string"))
	user := b.userAccount("actor.user")
	b.host("device")

	// A stub email-message SCO (message_id only) lets the click stitch to the
	// full message if it is (or becomes) in the graph (§4.11).
	var msgID identity.STIXID
	if msgUID := pathStr(p, "email.message_uid"); msgUID != "" {
		msgID = b.addSCO(
			n.r.EmailMessage(msgUID, "", "", evt.Time),
			identity.TypeEmailMessage,
			map[string]any{"message_id": msgUID},
		)
	}

	if user != "" && urlID != "" {
		b.addRel(RelClicked, user, urlID)
	}
	if msgID != "" && urlID != "" {
		b.addRel(RelContains, msgID, urlID)
	}

	return b.finish(nil), nil
}

// stringifyRefs renders a ref slice for storage in SCO properties.
func stringifyRefs(refs []identity.STIXID) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, string(r))
	}
	return out
}
