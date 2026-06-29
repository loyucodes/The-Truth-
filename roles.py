"""
roles.py — Role definitions and permission matrix for the TRUTH publication.
Single source of truth: every permission check references these constants.
"""

# ── Role slugs (stored in DB) ─────────────────────────────────────────
class Role:
    # Publishers — can create, edit, publish posts
    EDITORIAL_ADVISER        = "editorial_adviser"
    EDITOR_IN_CHIEF          = "editor_in_chief"
    ASSOC_EDITOR_IN_CHIEF    = "assoc_editor_in_chief"
    MANAGING_EDITOR          = "managing_editor"
    ASSOC_MANAGING_EDITOR    = "assoc_managing_editor"

    # Section editors — board contributors (read/react only, 1 per role)
    NEWS_EDITOR              = "news_editor"
    FEATURES_EDITOR          = "features_editor"
    SPORTS_EDITOR            = "sports_editor"
    SCI_TECH_EDITOR          = "sci_tech_editor"
    LITERARY_EDITOR          = "literary_editor"

    # Production — board contributors (read/react only, 1 per role)
    SENIOR_LAYOUT_ARTIST     = "senior_layout_artist"
    JUNIOR_LAYOUT_ARTIST     = "junior_layout_artist"
    SENIOR_GRAPHIC_ARTIST    = "senior_graphic_artist"
    JUNIOR_GRAPHIC_ARTIST    = "junior_graphic_artist"
    SENIOR_PHOTOJOURNALIST   = "senior_photojournalist"
    JUNIOR_PHOTOJOURNALIST   = "junior_photojournalist"
    SENIOR_CARTOONIST        = "senior_cartoonist"
    JUNIOR_CARTOONIST        = "junior_cartoonist"

    # Writers — unlimited, read/react only (submit drafts, not publish)
    WRITER                   = "writer"

    # Unlimited, read/react only
    PHOTOJOURNALIST          = "photojournalist"
    CARTOONIST               = "cartoonist"

    # General audience — read/react only
    READER                   = "reader"


# ── Permission sets ───────────────────────────────────────────────────
class Permission:
    READ           = "read"
    REACT          = "react"           # like / comment
    SUBMIT_DRAFT   = "submit_draft"    # submit for review (writers)
    PUBLISH        = "publish"         # create / edit / publish posts
    MANAGE_USERS   = "manage_users"    # invite, assign roles, deactivate
    MANAGE_SITE    = "manage_site"     # site-wide settings


# ── Role → permission mapping ─────────────────────────────────────────
ROLE_PERMISSIONS: dict[str, set[str]] = {

    # ── Publishers ────────────────────────────────────────────────────
    Role.EDITORIAL_ADVISER: {
        Permission.READ, Permission.REACT,
        Permission.PUBLISH, Permission.SUBMIT_DRAFT,
        Permission.MANAGE_USERS, Permission.MANAGE_SITE,
    },
    Role.EDITOR_IN_CHIEF: {
        Permission.READ, Permission.REACT,
        Permission.PUBLISH, Permission.SUBMIT_DRAFT,
        Permission.MANAGE_USERS, Permission.MANAGE_SITE,
    },
    Role.ASSOC_EDITOR_IN_CHIEF: {
        Permission.READ, Permission.REACT,
        Permission.PUBLISH, Permission.SUBMIT_DRAFT,
        Permission.MANAGE_USERS,
    },
    Role.MANAGING_EDITOR: {
        Permission.READ, Permission.REACT,
        Permission.PUBLISH, Permission.SUBMIT_DRAFT,
        Permission.MANAGE_USERS,
    },
    Role.ASSOC_MANAGING_EDITOR: {
        Permission.READ, Permission.REACT,
        Permission.PUBLISH, Permission.SUBMIT_DRAFT,
    },

    # ── Section editors (board contributors) ──────────────────────────
    Role.NEWS_EDITOR:     {Permission.READ, Permission.REACT},
    Role.FEATURES_EDITOR: {Permission.READ, Permission.REACT},
    Role.SPORTS_EDITOR:   {Permission.READ, Permission.REACT},
    Role.SCI_TECH_EDITOR: {Permission.READ, Permission.REACT},
    Role.LITERARY_EDITOR: {Permission.READ, Permission.REACT},

    # ── Production board (read/react only) ────────────────────────────
    Role.SENIOR_LAYOUT_ARTIST:   {Permission.READ, Permission.REACT},
    Role.JUNIOR_LAYOUT_ARTIST:   {Permission.READ, Permission.REACT},
    Role.SENIOR_GRAPHIC_ARTIST:  {Permission.READ, Permission.REACT},
    Role.JUNIOR_GRAPHIC_ARTIST:  {Permission.READ, Permission.REACT},
    Role.SENIOR_PHOTOJOURNALIST: {Permission.READ, Permission.REACT},
    Role.JUNIOR_PHOTOJOURNALIST: {Permission.READ, Permission.REACT},
    Role.SENIOR_CARTOONIST:      {Permission.READ, Permission.REACT},
    Role.JUNIOR_CARTOONIST:      {Permission.READ, Permission.REACT},

    # ── Writers (unlimited, can submit drafts) ────────────────────────
    Role.WRITER: {Permission.READ, Permission.REACT, Permission.SUBMIT_DRAFT},

    # ── Production / audience (unlimited) ────────────────────────────
    Role.PHOTOJOURNALIST: {Permission.READ, Permission.REACT},
    Role.CARTOONIST:      {Permission.READ, Permission.REACT},
    Role.READER:          {Permission.READ, Permission.REACT},
}

# ── Singleton roles (max 1 account per role) ──────────────────────────
SINGLETON_ROLES: set[str] = {
    Role.EDITORIAL_ADVISER,
    Role.EDITOR_IN_CHIEF,
    Role.ASSOC_EDITOR_IN_CHIEF,
    Role.MANAGING_EDITOR,
    Role.ASSOC_MANAGING_EDITOR,
    Role.NEWS_EDITOR,
    Role.FEATURES_EDITOR,
    Role.SPORTS_EDITOR,
    Role.SCI_TECH_EDITOR,
    Role.LITERARY_EDITOR,
    Role.SENIOR_LAYOUT_ARTIST,
    Role.JUNIOR_LAYOUT_ARTIST,
    Role.SENIOR_GRAPHIC_ARTIST,
    Role.JUNIOR_GRAPHIC_ARTIST,
    Role.SENIOR_PHOTOJOURNALIST,
    Role.JUNIOR_PHOTOJOURNALIST,
    Role.SENIOR_CARTOONIST,
    Role.JUNIOR_CARTOONIST,
}

# ── Publisher roles (PUBLISH permission holders) ──────────────────────
PUBLISHER_ROLES: set[str] = {
    role for role, perms in ROLE_PERMISSIONS.items()
    if Permission.PUBLISH in perms
}

# ── Human-readable labels ─────────────────────────────────────────────
ROLE_LABELS: dict[str, str] = {
    Role.EDITORIAL_ADVISER:      "Editorial Adviser",
    Role.EDITOR_IN_CHIEF:        "Editor-in-Chief",
    Role.ASSOC_EDITOR_IN_CHIEF:  "Associate Editor-in-Chief",
    Role.MANAGING_EDITOR:        "Managing Editor",
    Role.ASSOC_MANAGING_EDITOR:  "Associate Managing Editor",
    Role.NEWS_EDITOR:            "News Editor",
    Role.FEATURES_EDITOR:        "Features Editor",
    Role.SPORTS_EDITOR:          "Sports Editor",
    Role.SCI_TECH_EDITOR:        "Sci-Tech Editor",
    Role.LITERARY_EDITOR:        "Literary Editor",
    Role.SENIOR_LAYOUT_ARTIST:   "Senior Layout Artist",
    Role.JUNIOR_LAYOUT_ARTIST:   "Junior Layout Artist",
    Role.SENIOR_GRAPHIC_ARTIST:  "Senior Graphic Artist",
    Role.JUNIOR_GRAPHIC_ARTIST:  "Junior Graphic Artist",
    Role.SENIOR_PHOTOJOURNALIST: "Senior Photojournalist",
    Role.JUNIOR_PHOTOJOURNALIST: "Junior Photojournalist",
    Role.SENIOR_CARTOONIST:      "Senior Cartoonist",
    Role.JUNIOR_CARTOONIST:      "Junior Cartoonist",
    Role.WRITER:                 "Writer",
    Role.PHOTOJOURNALIST:        "Photojournalist",
    Role.CARTOONIST:             "Cartoonist",
    Role.READER:                 "Reader",
}


# ── Helper ─────────────────────────────────────────────────────────────
def has_permission(role: str, permission: str) -> bool:
    """Return True if the given role has the given permission."""
    return permission in ROLE_PERMISSIONS.get(role, set())
