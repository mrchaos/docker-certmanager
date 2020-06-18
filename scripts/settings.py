LOGGING_CONFIG = {
    "version": 1,
    "formatters": {
        "default": {
            "format": "%(levelname)s - %(name)s - %(asctime)s - %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
        },
    },
    "loggers": {
        "pygluu.containerlib": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": True,
        },
        "certman": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        # "wait": {
        #     "handlers": ["console"],
        #     "level": "INFO",
        #     "propagate": False,
        # },
    },
    # "root": {
    #     "level": "INFO",
    #     "handlers": ["console"],
    # },
}

#: source `from-files` constant
FROM_FILES = "from-files"

#: source `self-generate` constant
SELF_GENERATE = "self-generate"

SERVICE_NAMES = (
    "web",
    "oxshibboleth",
    "oxauth",
    "oxd",
)

SOURCE_TYPES = (
    FROM_FILES,
    SELF_GENERATE,
)
