import logging
import sys

class AppLogger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("app.log", encoding="utf-8")
        ]
    )
    _logger = logging.getLogger("AppLogger")

    @staticmethod
    def info(message: str, *args, **kwargs):
        AppLogger._logger.info(message, *args, **kwargs)

    @staticmethod
    def warning(message: str, *args, **kwargs):
        AppLogger._logger.warning(message, *args, **kwargs)

    @staticmethod
    def error(message: str, *args, **kwargs):
        AppLogger._logger.error(message, *args, **kwargs)

    @staticmethod
    def debug(message: str, *args, **kwargs):
        AppLogger._logger.debug(message, *args, **kwargs)
