from flask import Blueprint

# Crear el Blueprint para "expenses"
expenses_bp = Blueprint('expenses', __name__)

from . import routes  # Importar los endpoints desde routes.py