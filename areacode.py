#!/usr/bin/python

# Telephone Area Code to Approximate Location
# Author: V. Alex Brennen <vab@mit.edu>
# License: This script is public domain
# Date: 2012-06-05

# Description: This script will attempt to use the area code data from
#              Wikipedia to resolve area codes given on the command line
#              to approximate geographic locations.

import sys
import re


# A regular expression to search for the pattern of three numerical digits
areacode = re.compile(r'^\d{3}$')


# A dictionary of area codes to approximate geographic locations
# This information derived from http://en.wikipedia.org/wiki/List_of_area_codes
area_codes = {
	'201' : 'New Jersey (Hackensack, Jersey City)',
	'202' : 'Washington, D.C.',
	'203' : 'Connecticut (Bridgeport, New Haven)',
	'204' : 'Manitoba',
	'205' : 'Alabama (Birmingham)',
	'206' : 'State of Washington (Seattle)',
	'207' : 'Maine',
	'208' : 'Idaho',
	'209' : 'California (Stockton, Modesto)',
	'210' : 'Texas ',
	'212' : 'New York City',
	'213' : 'California (L.A.)',
	'214' : 'Texas (Dallas-Fort Worth)',
	'215' : 'Pennsylvania (Philadelphia)',
	'216' : 'Ohio (Cleveland)',
	'217' : 'Illinois (Springfield)',
	'218' : 'Minnesota (Duluth)',
	'219' : 'Indiana (Gary)',
	'224' : 'Illinois (northeastern)',
	'225' : 'Louisiana (Baton Rouge)',
	'226' : 'Ontario',
	'227' : 'Maryland',
	'228' : 'Mississippi (Gulfport)',
	'229' : 'Georgia (Albany)',
	'231' : 'Michigan (Muskegon)',
	'234' : 'Ohio',
	'236' : 'British Columbia',
	'239' : 'Florida (southwest coast)',
	'240' : 'Maryland',
	'242' : 'Bahamas',
	'246' : 'Barbados',
	'248' : 'Michigan (Oakland County)',
	'249' : 'Ontario (northeastern Ontario and central Ontario)',
	'250' : 'British Columbia (Victoria)',
	'251' : 'Alabama (Mobile County)',
	'252' : 'North Carolina (Greenville)',
	'253' : 'State of Washington (Tacoma)',
	'254' : 'Texas (Waco)',
	'256' : 'Alabama (Huntsville)',
	'260' : 'Indiana (Fort Wayne)',
	'262' : 'Wisconsin (Racine)',
	'264' : 'Anguilla',
	'267' : 'Pennsylvania (Philadelphia)',
	'268' : 'Antigua and Barbuda',
	'269' : 'Michigan (Battle Creek)',
	'270' : 'Kentucky (western)',
	'272' : 'Pennsylvania (northeastern)',
	'274' : 'Wisconsin',
	'276' : 'Virginia (Bristol)',
	'281' : 'Texas',
	'283' : 'Ohio (southwest)',
	'284' : 'British Virgin Islands',
	'289' : 'Ontario',
	'301' : 'Maryland (Silver Spring)',
	'302' : 'Delaware',
	'303' : 'Colorado (Denver, Boulder)',
	'304' : 'West Virginia',
	'305' : 'Florida (Miami-Dade County)',
	'306' : 'Saskatchewan',
	'307' : 'Wyoming',
	'308' : 'Nebraska',
	'309' : 'Illinois (Peoria)',
	'310' : 'California (Beverly Hills)',
	'312' : 'Illinois (downtown Chicago)',
	'313' : 'Michigan (Dearborn, Detroit)',
	'314' : 'Missouri (St. Louis)',
	'315' : 'New York (Syracuse)',
	'316' : 'Kansas (Wichita)',
	'317' : 'Indiana (Indianapolis)',
	'318' : 'Louisiana (Shreveport)',
	'319' : 'Iowa (Cedar Rapids)',
	'320' : 'Minnesota (St. Cloud)',
	'321' : 'Florida (Orlando)',
	'323' : 'California (western Los Angeles)',
	'325' : 'Texas (Abilene)',
	'327' : 'Arkansas (Texarkana)',
	'330' : 'Ohio (Akron)',
	'331' : 'Illinois (Aurora)',
	'334' : 'Alabama (Montgomery)',
	'336' : 'North Carolina (Greensboro)',
	'337' : 'Louisiana (Lafayette)',
	'339' : 'Massachusetts',
	'340' : 'U.S. Virgin Islands',
	'341' : 'California (San Francisco)',
	'343' : 'Ontario (Ottawa)',
	'345' : 'Cayman Islands',
	'347' : 'New York City',
	'351' : 'Massachusetts',
	'352' : 'Florida (Gainesville)',
	'360' : 'State of Washington (Olympia, Vancouver)',
	'361' : 'Texas (Corpus Christi)',
	'364' : 'Kentucky',
	'365' : 'Ontario',
	'369' : 'California (northwest)',
	'380' : 'Ohio',
	'385' : 'Utah',
	'386' : 'Florida (Daytona Beach)',
	'387' : 'Toronto',
	'401' : 'Rhode Island',
	'402' : 'Nebraska (Omaha)',
	'403' : 'Alberta (Calgary)',
	'404' : 'Georgia (Atlanta)',
	'405' : 'Oklahoma (Oklahoma City)',
	'406' : 'Montana',
	'407' : 'Florida (Orlando)',
	'408' : 'California (San Jose)',
	'409' : 'Texas (Beaumont, Galveston)',
	'410' : 'Maryland',
	'412' : 'Pennsylvania (Pittsburgh metropolitan area)',
	'413' : 'Massachusetts (Springfield)',
	'414' : 'Wisconsin (Milwaukee County)',
	'415' : 'California (San Francisco)',
	'416' : 'Ontario (Toronto)',
	'417' : 'Missouri (Springfield)',
	'418' : 'Quebec',
	'419' : 'Ohio (Toledo)',
	'423' : 'Tennessee (eastern)',
	'424' : 'California (L.A.)',
	'425' : 'State of Washington (Seattle suburbs)',
	'430' : 'Texas',
	'431' : 'Manitoba',
	'432' : 'Texas (western)',
	'434' : 'Virginia (Charlottesville)',
	'435' : 'Utah (Cedar City)',
	'437' : 'Province of Ontario (Toronto metropolitan area)',
	'438' : 'Province of Quebec (Montreal metropolitan area)',
	'440' : 'Ohio (Cleveland surrounding areas)',
	'441' : 'Bermuda',
	'442' : 'California (inland, southern)',
	'443' : 'Maryland (mostly cellular)',
	'445' : 'Pennsylvania (Philadelphia) & Arizona (Tucson)',
	'447' : 'Illinois',
	'450' : 'Quebec (central southern)',
	'458' : 'Oregon (Eugene)',
	'464' : 'Illinois',
	'469' : 'Texas',
	'470' : 'Georgia',
	'473' : 'Grenada',
	'475' : 'Connecticut',
	'478' : 'Georgia (Macon)',
	'479' : 'Arkansas (northwestern)',
	'480' : 'Arizona (Scottsdale/Phoenix)',
	'484' : 'Pennsylvania',
	'501' : 'Arkansas (Little Rock)',
	'502' : 'Kentucky (Louisville)',
	'503' : 'Oregon (Portland)',
	'504' : 'Louisiana New Orleans)',
	'505' : 'New Mexico (Albuquerque)',
	'506' : 'New Brunswick',
	'507' : 'Minnesota (Rochester)',
	'508' : 'Massachusetts (Worcester)',
	'509' : 'State of Washington (eastern)',
	'510' : 'California (Oakland)',
	'512' : 'Texas (Austin)',
	'513' : 'Ohio (Cincinnati)',
	'514' : 'Province of Quebec',
	'515' : 'Iowa (Des Moines)',
	'516' : 'New York State (Nassau County)',
	'517' : 'Michigan (Lansing)',
	'518' : 'New York State (Albany)',
	'519' : 'Province of Ontario (London, Windsor)',
	'520' : 'Arizona (Tucson)',
	'530' : 'California (Redding)',
	'531' : 'Nebraska (Omaha)',
	'534' : 'Wisconsin',
	'539' : 'Oklahoma (Tulsa)',
	'540' : 'Virginia (Fredericksburg)',
	'541' : 'Oregon (Eugene)',
	'551' : 'New Jersey',
	'557' : 'Missouri',
	'559' : 'California (Fresno)',
	'561' : 'Florida (Palm Beach County)',
	'562' : 'California (Long Beach)',
	'563' : 'Iowa (Davenport)',
	'564' : 'State of Washington (western)',
	'567' : 'Ohio',
	'570' : 'Pennsylvania (Scranton)',
	'571' : 'Virginia',
	'573' : 'Missouri (Columbia)',
	'574' : 'Indiana (South Bend)',
	'575' : 'New Mexico (Las Cruces)',
	'579' : 'Province of Quebec (central southern)',
	'580' : 'Oklahoma (Ponca City)',
	'581' : 'Province of Quebec',
	'582' : 'Pennsylvania',
	'585' : 'New York State (Rochester)',
	'586' : 'Michigan (Warren)',
	'587' : 'Alberta',
	'601' : 'Mississippi (Jackson)',
	'602' : 'Arizona (downtown Phoenix)',
	'603' : 'New Hampshire',
	'604' : 'British Columbia (greater Vancouver Regional District)',
	'605' : 'South Dakota',
	'606' : 'Kentucky (Ashland, Pikeville)',
	'607' : 'New York State (Binghamton)',
	'608' : 'Wisconsin (Madison)',
	'609' : 'New Jersey (Trenton)',
	'610' : 'Pennsylvania (Allentown, Reading)',
	'612' : 'Minnesota (Minneapolis)',
	'613' : 'Province of Ontario (Ottawa and eastern Ontario)',
	'614' : 'Ohio (Columbus and Franklin County)',
	'615' : 'Tennessee (Nashville)',
	'616' : 'Michigan (Grand Rapids)',
	'617' : 'Massachusetts (Boston)',
	'618' : 'Illinois (southern)',
	'619' : 'California (San Diego)',
	'620' : 'Kansas (southern Kansas)',
	'623' : 'Arizona (Maricopa County)',
	'626' : 'California (Pasadena)',
	'627' : 'California (northern coast)',
	'628' : 'California (San Francisco)',
	'630' : 'Illinois (Aurora, Naperville)',
	'631' : 'New York State (Suffolk County on Long Island)',
	'636' : 'Missouri (St. Charles)',
	'639' : 'Saskatchewan',
	'641' : 'Iowa (Mason City)',
	'646' : 'New York State (Manhattan)',
	'647' : 'Province of Ontario',
	'649' : 'Turks and Caicos Islands',
	'650' : 'California (Palo Alto)',
	'651' : 'Minnesota (St. Paul)',
	'657' : 'California',
	'658' : 'Jamaica',
	'659' : 'Alabama',
	'660' : 'Missouri (Sedalia, Kirksville)',
	'661' : 'California (Bakersfield)',
	'662' : 'Mississippi (Tupelo, Columbus)',
	'664' : 'Montserrat',
	'667' : 'Maryland',
	'669' : 'California',
	'670' : 'Northern Mariana Islands',
	'671' : 'Guam',
	'672' : 'British Columbia',
	'678' : 'Georgia (Atlanta)',
	'679' : 'Michigan (Detroit)',
	'681' : 'West Virginia',
	'682' : 'Texas',
	'684' : 'American Samoa',
	'689' : 'Florida (central)',
	'701' : 'North Dakota',
	'702' : 'Nevada (Clark County)',
	'703' : 'Virginia (northern)',
	'704' : 'North Carolina (Charlotte)',
	'705' : 'Ontario (northeastern)',
	'706' : 'Georgia (Augusta, Columbus)',
	'707' : 'California (Vallejo, Crescent City)',
	'708' : 'Illinois (Chicago suburbs)',
	'709' : 'Newfoundland and Labrador',
	'712' : 'Iowa (Sioux City)',
	'713' : 'Texas (Houston)',
	'714' : 'California (Orange County)',
	'715' : 'Wisconsin (northern)',
	'716' : 'New York State (Buffalo, Niagara Falls)',
	'717' : 'Pennsylvania (Harrisburg, Gettysburg)',
	'718' : 'New York State (New York City except Manhattan)',
	'719' : 'Colorado (Colorado Springs, Pueblo)',
	'720' : 'Colorado (Denver area)',
	'721' : 'Sint Maarten',
	'724' : 'Pennsylvania (southwestern)',
	'727' : 'Florida (Pinellas County)',
	'730' : 'Illinois',
	'731' : 'Tennessee (western)',
	'732' : 'New Jersey (New Brunswick)',
	'734' : 'Michigan (Ann Arbor)',
	'737' : 'Texas',
	'740' : 'Ohio (suburban Columbus, central Ohio)',
	'742' : 'Ontario',
	'747' : 'California (Los Angeles County, San Fernando Valley)',
	'754' : 'Florida (southeastern)',
	'757' : 'Virginia (east shore)',
	'758' : 'Saint Lucia',
	'760' : 'California (southern)',
	'761' : 'Florida (Palm Beach County)',
	'762' : 'Georgia',
	'763' : 'Minnesota (Maple Grove, Monticello)',
	'764' : 'California (western San Francisco Bay)',
	'765' : 'Indiana (Lafayette, Marion)',
	'767' : 'Commonwealth of Dominica',
	'769' : 'Mississippi',
	'770' : 'Georgia (Marietta, southern)',
	'772' : 'Florida (Fort Pierce, Port Saint Lucie)',
	'773' : 'Illinois (Chicago excluding downtown)',
	'774' : 'Massachusetts (western)',
	'775' : 'Nevada (Carson City, Reno)',
	'778' : 'British Columbia',
	'779' : 'Illinois',
	'780' : 'Alberta (Edmonton)',
	'781' : 'Massachusetts (suburbs of Boston)',
	'784' : 'Saint Vincent and the Grenadines',
	'785' : 'Kansas (Topeka)',
	'786' : 'Florida (Miami-Dade County)',
	'787' : 'Puerto Rico',
	'800' : 'Toll-free telephone service',
	'801' : 'Utah (Wasatch Front)',
	'802' : 'Vermont',
	'803' : 'South Carolina (Columbia)',
	'804' : 'Virginia (Richmond Metropolitan Area)',
	'805' : 'California (Ventura, San Luis Obispo, and Santa Barbara counties)',
	'806' : 'Texas (Lubbock, Amarillo)',
	'807' : 'Province of Ontario (northwestern)',
	'808' : 'Hawaii',
	'809' : 'Dominican Republic',
	'810' : 'Michigan (Port Huron, Flint)',
	'812' : 'Indiana (southern Indiana)',
	'813' : 'Florida (Tampa)',
	'814' : 'Pennsylvania (Erie)',
	'815' : 'Illinois (Rockford, La Salle, DeKalb)',
	'816' : 'Missouri (Kansas City)',
	'817' : 'Texas (Fort Worth, Arlington)',
	'818' : 'California (San Fernando Valley of Los Angeles County)',
	'819' : 'Province of Quebec',
	'825' : 'Alberta',
	'828' : 'North Carolina (Asheville, Franklin)',
	'829' : 'Dominican Republic',
	'830' : 'Texas (Del Rio, Kerrville)',
	'831' : 'California (Monterey, Salinas, Monterey County)',
	'832' : 'Texas',
	'833' : 'Toll-free telephone service',
	'843' : 'South Carolina (Charleston, Florence)',
	'844' : 'Toll-free telephone service',
	'845' : 'New York State (southeastern)',
	'847' : 'Illinois (Arlington Heights)',
	'848' : 'New Jersey',
	'849' : 'Dominican Republic',
	'850' : 'Florida (northwestern)',
	'855' : 'Toll-free telephone service',
	'856' : 'New Jersey (Cherry Hill, Camden)',
	'857' : 'Massachusetts (Boston suburbs)',
	'858' : 'California (southern)',
	'859' : 'Kentucky (Lexington, Richmond)',
	'860' : 'Connecticut (Hartford, Bristol)',
	'862' : 'New Jersey',
	'863' : 'Florida (Lakeland, south-central)',
	'864' : 'South Carolina (Greenville, Spartanburg)',
	'865' : 'Tennessee (Knoxville)',
	'866' : 'Toll-free telephone service',
	'867' : 'Yukon, Northwest Territories, and Nunavut',
	'868' : 'Trinidad and Tobago',
	'869' : 'Saint Kitts and Nevis',
	'870' : 'Arkansas (Texarkana, Jonesboro)',
	'872' : 'Illinois',
	'873' : 'Province of Quebec',
	'876' : 'Jamaica',
	'877' : 'Toll-free telephone service',
	'878' : 'Pennsylvania',
	'888' : 'Toll-free telephone service',
	'900' : 'Premium-rate telephone service',
	'901' : 'Tennessee (Memphis)',
	'902' : 'Nova Scotia and Prince Edward Island',
	'903' : 'Texas (Tyler, northeast Texas)',
	'904' : 'Florida (Jacksonville)',
	'905' : 'Province of Ontario (Toronto suburbs)',
	'906' : 'Michigan (upper peninsula)',
	'907' : 'Alaska',
	'908' : 'New Jersey (west central)',
	'909' : 'California (south western)',
	'910' : 'North Carolina (Fayetteville, Wilmington)',
	'912' : 'Georgia (Savannah, Statesboro)',
	'913' : 'Kansas (Kansas City)',
	'914' : 'New York State (Westchester County)',
	'915' : 'Texas (El Paso County)',
	'916' : 'California (Sacramento Metropolitan Area)',
	'917' : 'New York (New York City; cellular telephones)',
	'918' : 'Oklahoma (Tulsa)',
	'919' : 'North Carolina (Raleigh)',
	'920' : 'Wisconsin (Appleton, Sheboygan)',
	'925' : 'California (Livermore, Concord)',
	'928' : 'Arizona (Flagstaff)',
	'929' : 'New York',
	'931' : 'Tennessee (middle)',
	'935' : 'California (San Diego)',
	'936' : 'Texas (southeastern)',
	'937' : 'Ohio (Dayton)',
	'938' : 'Alabama (Huntsville)',
	'939' : 'Puerto Rico',
	'940' : 'Texas (north of Dallas-Ft. Worth)',
	'941' : 'Florida (south eastern gulf coast)',
	'947' : 'Michigan',
	'949' : 'California (Irvine, Lake Forest)',
	'951' : 'California (western Riverside County)',
	'952' : 'Minnesota (Bloomington)',
	'954' : 'Florida (Broward County, Fort Lauderdale)',
	'956' : 'Texas (Laredo)',
	'959' : 'Connecticut',
	'970' : 'Colorado (north-central, south-central, western)',
	'971' : 'Oregon (Portland)',
	'972' : 'Texas',
	'973' : 'New Jersey (Newark)',
	'975' : 'Missouri',
	'978' : 'Massachusetts (northeastern)',
	'979' : 'Texas (southeastern)',
	'980' : 'North Carolina',
	'984' : 'North Carolina',
	'985' : 'Louisiana (southeastern)',
	'989' : 'Michigan (central)'
}


# This function resolves the area code through the area_codes dictionary.
def resolv_code(ac):
	"""Attempts to look up the three digit area code in the area_codes dictionary defined in the script."""
	if area_codes.has_key(ac):
		print ac, ": ", area_codes[ac]
	else:
		print ac, ": ", "Area code not found."
	return 0


# This function will print out the usage information
def usage():
	"""Prints usage information and exits."""
	print "Usage: areacode.py (space separated area codes)"
	print "Example: areacode.py 603 617 415"
	print "Options: -h      This Help Text"
	print "         --help  This Help Text"
	print
	sys.exit(0)


# If the script isn't given any area codes to resolve, it should provide
# usage information and exit.
if len(sys.argv) < 2:
	usage()


# The main loop. It calls the resolver function for each of the arguments 
# given on the command line that match the three number regular expression.
# If it encounters a help request, it calls the usage() function to print
# the usage information and exit the program.
for arg in sys.argv[1:]:
	if areacode.match(arg):
		resolv_code(ac=arg)
	elif (arg == "-h" or arg == "--help"):
		usage()
	else:
		continue
