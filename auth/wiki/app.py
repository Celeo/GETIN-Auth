from flask import Blueprint, render_template, request, flash, url_for, redirect
from flask_login import login_required, current_user

from auth.shared import db
from .models import Namespace, Page, Revision


app = Blueprint('wiki', __name__, template_folder='templates/wiki', static_folder='static')


@app.route('/')
def index():
    return redirect(url_for('.page', namespace='public', name='Index'))


@app.route('/sitemap')
def sitemap():
    namespaces = Namespace.query
    if not current_user.is_authenticated:
        namespaces = namespaces.filter_by(private=False)
    namespaces = namespaces.all()
    return render_template('wiki/sitemap.html', namespaces=namespaces)


@app.route('/recent_changes')
@login_required
def recent_changes():
    revisions = Revision.query.order_by(Revision.id.desc()).limit(20).all()
    return render_template('wiki/recent_changes.html', revisions=revisions)


@app.route('/review/all')
@login_required
def review_changes():
    if not current_user.is_authenticated or not current_user.wiki_mod:
        return redirect('/')
    return render_template('wiki/review_all.html')


@app.route('/admin')
@login_required
def admin():
    if not current_user.is_authenticated or not current_user.admin:
        return redirect('/')
    return render_template('wiki/admin.html')


@app.route('/<namespace>/<name>/edit', methods=['GET', 'POST'])
@login_required
def edit(namespace, name):
    ns = Namespace.query.filter_by(name=namespace).first()
    if not ns:
        flash('Unknown namespace \'' + namespace + '\'', 'danger')
        return redirect(url_for('.sitemap'))
    page = Page.query.filter_by(name=name, namespace_id=ns.id).first()
    if request.method == 'POST':
        contents = request.form['content']
        if not page:
            page = Page(ns.id, name, '')
            db.session.add(page)
            db.session.commit()
        r = Revision(page.id, current_user.id, contents)
        db.session.add(r)
        page.contents = contents
        db.session.commit()
        return 'Saved'
    return render_template('wiki/edit.html', namespace=namespace, name=name, page=page, ns=ns)


@app.route('/<namespace>/<name>/history')
@login_required
def history(namespace, name):
    ns = Namespace.query.filter_by(name=namespace).first()
    if not ns:
        flash('Unknown namespace \'' + namespace + '\'', 'danger')
        return redirect(url_for('.sitemap'))
    page = Page.query.filter_by(name=name, namespace_id=ns.id).first()
    return render_template('wiki/history.html', namespace=namespace, name=name, page=page, ns=ns)


@app.route('/revision/<int:id>')
@login_required
def revision(id):
    rev = Revision.query.get(id)
    prev = rev.page.revisions.filter(Revision.id < rev.id).order_by(Revision.id.desc()).first()
    rev_back = prev.id if prev else None
    next = rev.page.revisions.filter(Revision.id > rev.id).first()
    rev_next = next.id if next else None
    return render_template('wiki/revision.html', revision=rev, previous=prev, back=rev_back, next=rev_next)


@app.route('/<namespace>/<name>')
def page(namespace, name):
    ns = Namespace.query.filter_by(name=namespace).first()
    if not ns:
        flash('Unknown namespace \'' + namespace + '\'', 'danger')
        return redirect(url_for('.sitemap'))
    if ns.private and not current_user.is_authenticated:
        flash('You cannot view this page.', 'danger')
        return redirect(url_for('.sitemap'))
    page = Page.query.filter_by(name=name, namespace_id=ns.id).first()
    if not page:
        flash('This page doesn\'t exist. You can create it here.', 'warning')
        return redirect(url_for('.edit', namespace=namespace, name=name))
    return render_template('wiki/page.html', namespace=namespace, name=name, page=page, ns=ns)


@app.route('/<name>')
@app.route('/<name>/')
def view_namespace(name):
    ns = Namespace.query.filter_by(name=name).first()
    if not ns:
        flash('Unknown namespace \'' + name + '\'', 'danger')
        return redirect(url_for('.sitemap'))
    return render_template('wiki/namespace.html', name=name, ns=ns)


@app.errorhandler(404)
def error_404(e):
    flash('Page not found', 'danger')
    return redirect(url_for('.sitemap'))
