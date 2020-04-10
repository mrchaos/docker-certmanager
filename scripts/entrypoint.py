import logging
import logging.config

import click

from pygluu.containerlib import get_manager

from settings import LOGGING_CONFIG
from settings import SELF_GENERATE
from settings import SERVICE_NAMES
from settings import SOURCE_TYPES
from oxauth_patcher import OxauthPatcher
from oxshibboleth_patcher import OxshibbolethPatcher
from web_patcher import WebPatcher

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("certman")

# ============
# CLI commands
# ============

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    pass


@cli.command()
@click.argument(
    "service",
    type=click.Choice(SERVICE_NAMES),
)
@click.option(
    "--source",
    help="Source type (default to self-generate).",
    type=click.Choice(SOURCE_TYPES),
    default=SELF_GENERATE,
)
@click.option(
    "--dry-run",
    help="Generate save certs and/or crypto keys only without saving it to external backends.",
    is_flag=True,
)
@click.option(
    "--opts",
    help="Options for targeted service (can be set multiple times).",
    multiple=True,
    metavar="KEY:VALUE",
)
def patch(service, source, dry_run, opts):
    """Patch cert and/or crypto keys for the targeted service.
    """
    manager = get_manager()

    if dry_run:
        logger.warn("Dry-run mode is enabled!")

    callback_classes = {
        "web": WebPatcher,
        "oxshibboleth": OxshibbolethPatcher,
        "oxauth": OxauthPatcher,
    }

    logger.info("Processing updates for service '{}' using "
                "source type '{}'".format(service, source))

    _opts = {}
    for opt in opts:
        try:
            k, v = opt.split(":", 1)
            _opts[k] = v
        except ValueError:
            k = opt
            v = ""

    callback_cls = callback_classes[service]
    callback_cls(manager, source, dry_run, **_opts).patch()


if __name__ == "__main__":
    cli()
