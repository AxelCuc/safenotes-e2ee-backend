"""CRUD de notas cifradas.

El servidor NUNCA ve texto plano: recibe y devuelve `ciphertext` + `iv`.
Prevención de IDOR: TODA consulta filtra por `owner_id == usuario de la sesión`.
Si la nota existe pero es de otro usuario, se responde 404 (igual que si no existiera).
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import get_current_user
from ..models import Note, User
from ..ratelimit import rate_limit
from ..schemas import NoteIn, NoteOut

router = APIRouter(
    prefix="/api/notes",
    tags=["notes"],
    dependencies=[Depends(rate_limit("notes", 120, 60))],
)


def _get_owned_note(db: Session, note_id: uuid.UUID, user: User) -> Note:
    note = db.scalar(
        select(Note).where(Note.id == str(note_id), Note.owner_id == user.id)
    )
    if note is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nota no encontrada.")
    return note


@router.get("", response_model=list[NoteOut])
def list_notes(
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0, le=100_000),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    notes = db.scalars(
        select(Note)
        .where(Note.owner_id == user.id)
        .order_by(Note.updated_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return [NoteOut.model_validate(n) for n in notes]


@router.post("", response_model=NoteOut, status_code=status.HTTP_201_CREATED)
def create_note(
    data: NoteIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    total = db.scalar(select(func.count()).select_from(Note).where(Note.owner_id == user.id))
    if total >= settings.max_notes_per_user:
        raise HTTPException(status.HTTP_409_CONFLICT, "Alcanzaste el límite de notas.")
    note = Note(owner_id=user.id, ciphertext=data.ciphertext, iv=data.iv)
    db.add(note)
    db.commit()
    db.refresh(note)
    return NoteOut.model_validate(note)


@router.get("/{note_id}", response_model=NoteOut)
def get_note(
    note_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return NoteOut.model_validate(_get_owned_note(db, note_id, user))


@router.put("/{note_id}", response_model=NoteOut)
def update_note(
    note_id: uuid.UUID,
    data: NoteIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    note = _get_owned_note(db, note_id, user)
    note.ciphertext = data.ciphertext
    note.iv = data.iv
    db.commit()
    db.refresh(note)
    return NoteOut.model_validate(note)


@router.delete("/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_note(
    note_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    note = _get_owned_note(db, note_id, user)
    db.delete(note)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
