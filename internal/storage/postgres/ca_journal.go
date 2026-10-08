package postgres

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"
)

// CAJournal stores only public integrity metadata, never certificate private
// keys. Secret Manager holds the original complete bundle in a root-only secret.
type CAJournal struct{ Store *Store }

var journalHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var journalSecret = regexp.MustCompile(`^projects/(?:[a-z][a-z0-9-]{4,62}|[0-9]+)/secrets/[A-Za-z0-9_-]{1,255}$`)

func (j CAJournal) Load(ctx context.Context, reference string) (stepca.Publication, error) {
	var p stepca.Publication
	if j.Store == nil || !journalHash.MatchString(reference) {
		return p, errors.New("invalid CA journal reference")
	}
	ctx, cancel := j.Store.bounded(ctx)
	defer cancel()
	rows, e := j.Store.pool.Query(ctx, `SELECT secret,sha256,version,published FROM bootstrap_private.ca_publication WHERE reference=$1`, reference)
	if e != nil {
		return p, safeError(e)
	}
	defer rows.Close()
	if rows.Next() {
		if e = rows.Scan(&p.Secret, &p.SHA256, &p.Version, &p.Published); e != nil {
			return p, safeError(e)
		}
	}
	return p, safeError(rows.Err())
}
func (j CAJournal) Begin(ctx context.Context, reference string, p stepca.Publication) error {
	if j.Store == nil || !journalHash.MatchString(reference) || !journalHash.MatchString(p.SHA256) || !journalSecret.MatchString(p.Secret) || p.Version != "" || p.Published {
		return errors.New("invalid CA staging attempt")
	}
	ctx, cancel := j.Store.bounded(ctx)
	defer cancel()
	tx, e := j.Store.begin(ctx)
	if e != nil {
		return safeError(e)
	}
	defer rollback(tx)
	if _, e = tx.Exec(ctx, `INSERT INTO bootstrap_private.ca_publication(reference,secret,sha256) VALUES($1,$2,$3) ON CONFLICT(reference) DO NOTHING`, reference, p.Secret, p.SHA256); e != nil {
		return safeError(e)
	}
	var saved stepca.Publication
	if e = tx.QueryRow(ctx, `SELECT secret,sha256,version,published FROM bootstrap_private.ca_publication WHERE reference=$1`, reference).Scan(&saved.Secret, &saved.SHA256, &saved.Version, &saved.Published); e != nil {
		return safeError(e)
	}
	if saved != p {
		return errors.New("immutable CA staging attempt differs")
	}
	return safeError(commit(ctx, tx))
}
func (j CAJournal) Bind(ctx context.Context, reference, version string) error {
	if j.Store == nil || !journalHash.MatchString(reference) {
		return errors.New("invalid CA journal reference")
	}
	p, e := j.Load(ctx, reference)
	if e != nil {
		return e
	}
	if !strings.HasPrefix(version, p.Secret+"/versions/") || !regexp.MustCompile(`^[1-9][0-9]*$`).MatchString(strings.TrimPrefix(version, p.Secret+"/versions/")) {
		return errors.New("invalid exact CA staging version")
	}
	ctx, cancel := j.Store.bounded(ctx)
	defer cancel()
	tag, e := j.Store.pool.Exec(ctx, `UPDATE bootstrap_private.ca_publication SET version=$2 WHERE reference=$1 AND NOT published AND (version='' OR version=$2)`, reference, version)
	if e != nil {
		return safeError(e)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("CA staging version binding rejected")
	}
	return nil
}
func (j CAJournal) Published(ctx context.Context, reference string) error {
	if j.Store == nil || !journalHash.MatchString(reference) {
		return errors.New("invalid CA journal reference")
	}
	ctx, cancel := j.Store.bounded(ctx)
	defer cancel()
	tag, e := j.Store.pool.Exec(ctx, `UPDATE bootstrap_private.ca_publication SET published=true WHERE reference=$1 AND version<>''`, reference)
	if e != nil {
		return safeError(e)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("missing CA recovery binding")
	}
	return nil
}
