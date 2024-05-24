__authors__ = ["Adam Horák", "Ondřej Ondryáš"]

import logging

# Create a logger instance
logger = logging.getLogger("dr_logger")

# Set the log level
logger.setLevel(logging.INFO)
# Create a file handler
handler = logging.FileHandler("collector.log")
# Create a formatter
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
# Add the formatter to the handler
handler.setFormatter(formatter)
# Add the handler to the logger
logger.handlers.clear()
logger.addHandler(handler)

# A second logger specifically for thread exceptions
logger_thread = logging.getLogger("dr_logger_thread")
logger_thread.setLevel(logging.INFO)
handler_thread = logging.FileHandler("collector_thread_exceptions.log")
formatter_thread = logging.Formatter("%(asctime)s - %(name)s - %(message)s")
handler_thread.setFormatter(formatter_thread)
logger_thread.addHandler(handler_thread)

# A third logger specifically for the resolvers which tend to get quite verbose
logger_resolvers = logging.getLogger("dr_logger_resolvers")
handler_resolvers = logging.FileHandler("collector_resolvers.log")
handler_resolvers.setFormatter(formatter)
logger_resolvers.setLevel(logging.WARNING)
logger_resolvers.addHandler(handler_resolvers)
