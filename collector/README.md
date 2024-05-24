# Domain Enrichment Data Collector

Python CLI tool to source domain information from various sources. Uses MongoDB as dataset storage.

It works in two phases:

- **Loading**: Collects categorized domain names from various sources and stores it in a mongo database.
- **Resolving**: Resolves select domain data and adds it to the database records.

Both phases run independently. You can load directly from a file or use a source list to load from multiple sources. You can also load from a [MISP](https://www.misp-project.org/) feed.
Domains are stored for future resolving and the data can be updated incrementally.

## Requirements

- Python 3.9+
- MongoDB instance
- GeoIP databases

First, create a virtual environment and install the dependencies from **requirements.txt**. For example:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
``` 

To start, create a .env file in the root directory (or add to your environment directly) with the following variables:

```
DR_MONGO_URI=<mongo connection string>
DR_MISP_KEY=<misp api key if you have one>
```

Without the connection string, it will default to an unauthenticated local instance at `mongodb://localhost:27017/`.

Have a look at **config.py** where you can set various options, e.g.:
- the database name,
- MISP URL and source feeds for loading,
- DNS resolver IPs,
- timeouts,
- batch sizes and parallelization levels.

You also need to acquire a copy of the [GeoLite2 City and ASN databases](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) in the MaxMind DB file format. Place the **GeoLite2-ASN.mmdb** and **GeoLite2-City.mmdb** files in the **data/geolite** directory. 

## Usage

The interpreter invocation (ex. `python3`) will be omitted from the following examples. You can use `python`
or `python3` depending on your system. Use python version 3.9 or later.

Note that commands that provide interactivity can be used with the `-y` or `--yes` flag to skip the interactive prompts
and start straight away.

You can also get help at any point with the `--help` flag. Use it with commands to get information about the command and
its arguments. Use it with the main script to get a list of available commands.

### Loading

Start by loading domains into the database with the `load` or `load-misp` command. In both cases, use the *collection* option to set the target MongoDB collection for the loaded domains.


The loaded records will have the source, timestamps, and *category* attributes. The category is either inferred from the source or MISP feed configuration or set to *unknown*. When loading direct The category is meant to distinguish between
different types of domains, such as *malware* or *phishing*.

#### Loading from files

The `load` command loads from a file or a list of sources:

```
main.py load [options] <file>

Options:
  -c, --collection TEXT    The target MongoDB collection for the loaded domains
  -d, --direct             Load the file as a list of domain names, instead of interpreting it as a list of sources
  -t, --category           The category field (if using the -d flag)
```

You must provide a path to a file that will be read. If it contains a list of domain names to be loaded, use the
*direct* flag. In this case, you can use the *category* option to enter the value for the stored category attribute.

If *direct* is not used, the file will be read as a list of sources to load from. Source lists are CSV files described in the *Source Lists* section.


#### Loading from MISP

The `load-misp` command loads from a MISP instance:

```
main.py load-misp [options] <feed>

Options:
  -c, --collection TEXT    The target MongoDB collection for the loaded domains
```

Provide the name of the MISP feed to load from. The feeds are configured in **config.py** in the *MISP_FEEDS*
dictionary. The CLI will only allow feed names that are configured in the dictionary. You can also use the help flag to
get a list of available choices.

The feeds dictionary defines the available options (feed names) as keys and the values are a tuple of the feed ID from
MISP and the category the feed belongs to, such as *phishing*.

### Resolving

To resolve domains in the database, use the `resolve` command:

```
main.py resolve [options]

Options:
  -t, --type [basic|geo|icmp]  Data to resolve
  -c, --collection TEXT        Target collection
  -e, --retry-evaluated        Retry resolving fields that have failed before
  -f, --force                  Force resolving all domains that have already been resolved
  -n, --limit INTEGER          Limit number of domains to resolve
  -s, --sequential             Resolve domains sequentially instead of in parallel
```

Use the *type* option to specify the type of data to resolve. The default is *basic*. Resolving is separated into
different types to allow for more granular control over the resolving process. The available types are:

- **basic**: Resolves most of the data available in the database. Domain data include DNS, RDAP (or WHOIS), TLS certificates. For
  the found IPs, RDAP is queries.
- **geo**: Resolves the geolocation data for the IPs.
- **icmp**: Determine the alive status and RTT for all the IPs by pinging them.

Use the *collection* option to specify the MongoDB collection with the domains to resolve. If you don't provide the collection, it will default to
*benign*.

Use the *retry-evaluated* flag to retry resolving fields that have failed before. Failed means that the resolution for
that field could not be completed for some reason deemed unrecoverable. This is useful if you want to retry resolving
those.

Use the *limit* option to limit the number of domains to resolve. This is mostly used for debugging.

Use the *sequential* flag to resolve sequentially instead of in parallel worker threads.
Sequential resolving is much slower.

## Domain Data Format

Each domain name is stored in a document in the database. These follow a common loose schema, but not all fields are
guaranteed to be present. You can see how the data is structured in the **datatypes.py** file.

In addition to the data fields, the document stores remarks and timestamps for when each field was resolved. This allows
the program to skip resolving fields that have already been resolved or that failed for fatal reasons, such as a TLS
certificate simply not existing. The logic to determine whether a field should be resolved or not goes like this:

- If the field is empty and the timestamp is empty, resolve the field. Either it has never been resolved or it failed
  for a recoverable reason.
- If the field is empty and the timestamp is recorded, it means that the field failed to resolve for some fatal reason.
  Resolve only if the *retry-evaluated* flag is set.
- In all other cases, the field has been resolved and the timestamp is recorded. Skip resolving the field.

In general, for each type of data, there is a nested object with the data. For example, the *dns* field contains the DNS
data for the domain. The *ips* field contains a list of IP objects, each with its own fields.

Each document also stores timestamps for when the domain was sourced and when it was last resolved. The *source* field
contains the source URI that the domain was sourced from. The *category* field contains the category of malicious
activity that the domain is associated with.

## Source Lists

Source lists are CSV files that contain a list of sources to load from. See the [*data/blacklists.csv*](./data/blacklists.csv) file for an
example. There are several columns in the CSV file that can be used to specify the source URI and the category of
malicious activity:

- **source**: The source URI. This is the only required column.
- **category**: The category of malicious activity that the domain is associated with. This is optional and defaults to
  *unknown*. Irrelevant for benign domains for example. See above for a list of available categories.
- **category source**: This determines the source of the category. If set to the value *this*, the category will be
  taken from the *category* column. Other values (*txt* and *csv*) are used to read the category from the source itself.
  This is useful if the source contains the category in its data and it differs for each domain.

There are two more columns that are used when the category source is set to *txt* or *csv*. These modes read the source
as plain text or CSV respectively and use the category from the source itself. These two columns are used to specify how
to read the category from the source. They are:

- **getter**: The getter specifies how to get the category from the source.
    - for plain text sources, the getter is a regular expression that is matched against the current line in the source.
      The first capture group in the regex is used as the category.
    - for CSV sources, the getter specifies the delimiter and column number to get the category from. The format is
      *delimiter* immediately followed by *column*. For example, `;2` will use semicolon as the delimiter and find the
      column with index 2.
- **mapper**: The mapper is used to map the category from the source to the categories used by the program. It's a list
  of mappings in the format *regex*=*category* separated by semicolons. The first mapping that matches the category from
  the source is used. If no mapping matches, the category is set to *unknown*.

### Example for getters and mappers

Picture a plain text source that contains a list of domains and their categories in the format `domain - category`, for
example:

```
example.com - Mallware
example2.com - Fishing
example3.com - Phish
```

Since there are multiple categories, we need to set the category source to *txt* and specify the getter and mapper. The
getter will need to match the value after the dash and the mapper will need to map the category from the source to the
categories used by the program, since the source list uses different naming. Thus, our source list will have the
following for this source:

| source                       | category | cat. source | getter    | mapper                         |
|------------------------------|----------|-------------|-----------|--------------------------------|
| https://urls.org/domains.txt | -        | txt         | `-\s(.*)` | `Mallware=malware;.*=phishing` |

The getter captures everything after the dash and whitespace. The mapper maps `Mallware` to `malware` and everything
else to `phishing`. As you can see, this is fairly flexible and can be used to source various lists for the categories
used by the program.

### Using source lists with the source loader

The source loader takes source files from the list and can read plain text files, CSV files and JSON files. It can also
unzip archives containing these files. The format of the source file is determined by the file extension. If the file
extension is not recognized, the loader will try to read it as a plain text file.

To use a source list, simply provide the path to the source list file as the source URI. The source loader will then
read the source list and load domains from the sources in it. Specifying indices for the above mentioned columns is not
yet implemented, and the columns are hardcoded for use with the default source list. This is priority for the next
update.