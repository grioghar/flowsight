package paths

import "strings"

// place is a city with coordinates.
type place struct {
	City     string
	Lat, Lon float64
}

// Where each provider's regions are built. A region is a campus, not a
// city centre, but the difference is a few tens of kilometres against
// placements that were previously off by continents.
var awsRegions = map[string]place{
	"us-east-1": {"Ashburn, VA, US", 39.0438, -77.4874}, "us-east-2": {"Columbus, OH, US", 39.9612, -82.9988},
	"us-west-1": {"San Jose, CA, US", 37.3382, -121.8863}, "us-west-2": {"Boardman, OR, US", 45.8399, -119.7006},
	"ca-central-1": {"Montreal, QC, CA", 45.5017, -73.5673}, "ca-west-1": {"Calgary, AB, CA", 51.0447, -114.0719},
	"sa-east-1": {"São Paulo, BR", -23.5505, -46.6333}, "mx-central-1": {"Querétaro, MX", 20.5888, -100.3899},
	"eu-west-1": {"Dublin, IE", 53.3498, -6.2603}, "eu-west-2": {"London, GB", 51.5072, -0.1276}, "eu-west-3": {"Paris, FR", 48.8566, 2.3522},
	"eu-central-1": {"Frankfurt, DE", 50.1109, 8.6821}, "eu-central-2": {"Zurich, CH", 47.3769, 8.5417},
	"eu-north-1": {"Stockholm, SE", 59.3293, 18.0686}, "eu-south-1": {"Milan, IT", 45.4642, 9.19}, "eu-south-2": {"Zaragoza, ES", 41.6488, -0.8891},
	"me-south-1": {"Manama, BH", 26.2285, 50.586}, "me-central-1": {"Dubai, AE", 25.2048, 55.2708}, "il-central-1": {"Tel Aviv, IL", 32.0853, 34.7818},
	"af-south-1": {"Cape Town, ZA", -33.9249, 18.4241}, "ap-east-1": {"Hong Kong, HK", 22.3193, 114.1694},
	"ap-south-1": {"Mumbai, IN", 19.076, 72.8777}, "ap-south-2": {"Hyderabad, IN", 17.385, 78.4867},
	"ap-southeast-1": {"Singapore, SG", 1.3521, 103.8198}, "ap-southeast-2": {"Sydney, AU", -33.8688, 151.2093},
	"ap-southeast-3": {"Jakarta, ID", -6.2088, 106.8456}, "ap-southeast-4": {"Melbourne, AU", -37.8136, 144.9631},
	"ap-southeast-5": {"Kuala Lumpur, MY", 3.139, 101.6869}, "ap-southeast-7": {"Bangkok, TH", 13.7563, 100.5018},
	"ap-northeast-1": {"Tokyo, JP", 35.6762, 139.6503}, "ap-northeast-2": {"Seoul, KR", 37.5665, 126.978}, "ap-northeast-3": {"Osaka, JP", 34.6937, 135.5023},
	"cn-north-1": {"Beijing, CN", 39.9042, 116.4074}, "cn-northwest-1": {"Zhongwei, CN", 37.5, 105.19},
	"us-gov-west-1": {"Boardman, OR, US", 45.8399, -119.7006}, "us-gov-east-1": {"Columbus, OH, US", 39.9612, -82.9988},
}

var gcpRegions = map[string]place{
	"us-central1": {"Council Bluffs, IA, US", 41.2619, -95.8608}, "us-east1": {"Moncks Corner, SC, US", 33.1968, -80.0131},
	"us-east4": {"Ashburn, VA, US", 39.0438, -77.4874}, "us-east5": {"Columbus, OH, US", 39.9612, -82.9988},
	"us-south1": {"Dallas, TX, US", 32.7767, -96.797}, "us-west1": {"The Dalles, OR, US", 45.5946, -121.1787},
	"us-west2": {"Los Angeles, CA, US", 34.0522, -118.2437}, "us-west3": {"Salt Lake City, UT, US", 40.7608, -111.891}, "us-west4": {"Las Vegas, NV, US", 36.1699, -115.1398},
	"northamerica-northeast1": {"Montreal, QC, CA", 45.5017, -73.5673}, "northamerica-northeast2": {"Toronto, ON, CA", 43.6532, -79.3832},
	"northamerica-south1": {"Querétaro, MX", 20.5888, -100.3899}, "southamerica-east1": {"São Paulo, BR", -23.5505, -46.6333}, "southamerica-west1": {"Santiago, CL", -33.4489, -70.6693},
	"europe-west1": {"St. Ghislain, BE", 50.4489, 3.8186}, "europe-west2": {"London, GB", 51.5072, -0.1276}, "europe-west3": {"Frankfurt, DE", 50.1109, 8.6821},
	"europe-west4": {"Eemshaven, NL", 53.4486, 6.8319}, "europe-west6": {"Zurich, CH", 47.3769, 8.5417}, "europe-west8": {"Milan, IT", 45.4642, 9.19},
	"europe-west9": {"Paris, FR", 48.8566, 2.3522}, "europe-west10": {"Berlin, DE", 52.52, 13.405}, "europe-west12": {"Turin, IT", 45.0703, 7.6869},
	"europe-north1": {"Hamina, FI", 60.5693, 27.1878}, "europe-north2": {"Stockholm, SE", 59.3293, 18.0686}, "europe-central2": {"Warsaw, PL", 52.2297, 21.0122},
	"europe-southwest1": {"Madrid, ES", 40.4168, -3.7038}, "asia-east1": {"Changhua, TW", 24.0518, 120.5161}, "asia-east2": {"Hong Kong, HK", 22.3193, 114.1694},
	"asia-northeast1": {"Tokyo, JP", 35.6762, 139.6503}, "asia-northeast2": {"Osaka, JP", 34.6937, 135.5023}, "asia-northeast3": {"Seoul, KR", 37.5665, 126.978},
	"asia-south1": {"Mumbai, IN", 19.076, 72.8777}, "asia-south2": {"Delhi, IN", 28.6139, 77.209}, "asia-southeast1": {"Singapore, SG", 1.3521, 103.8198},
	"asia-southeast2": {"Jakarta, ID", -6.2088, 106.8456}, "australia-southeast1": {"Sydney, AU", -33.8688, 151.2093}, "australia-southeast2": {"Melbourne, AU", -37.8136, 144.9631},
	"me-west1": {"Tel Aviv, IL", 32.0853, 34.7818}, "me-central1": {"Doha, QA", 25.2854, 51.531}, "me-central2": {"Dammam, SA", 26.4207, 50.0888},
	"africa-south1": {"Johannesburg, ZA", -26.2041, 28.0473},
}

var azureRegions = map[string]place{
	"eastus": {"Boydton, VA, US", 36.6676, -78.3875}, "eastus2": {"Boydton, VA, US", 36.6676, -78.3875}, "centralus": {"Des Moines, IA, US", 41.5868, -93.625},
	"northcentralus": {"Chicago, IL, US", 41.8781, -87.6298}, "southcentralus": {"San Antonio, TX, US", 29.4241, -98.4936}, "westcentralus": {"Cheyenne, WY, US", 41.14, -104.8202},
	"westus": {"San Jose, CA, US", 37.3382, -121.8863}, "westus2": {"Quincy, WA, US", 47.2343, -119.8526}, "westus3": {"Phoenix, AZ, US", 33.4484, -112.074},
	"canadacentral": {"Toronto, ON, CA", 43.6532, -79.3832}, "canadaeast": {"Québec, QC, CA", 46.8139, -71.208},
	"brazilsouth": {"São Paulo, BR", -23.5505, -46.6333}, "brazilsoutheast": {"Rio de Janeiro, BR", -22.9068, -43.1729},
	"northeurope": {"Dublin, IE", 53.3498, -6.2603}, "westeurope": {"Amsterdam, NL", 52.3676, 4.9041}, "uksouth": {"London, GB", 51.5072, -0.1276}, "ukwest": {"Cardiff, GB", 51.4816, -3.1791},
	"francecentral": {"Paris, FR", 48.8566, 2.3522}, "francesouth": {"Marseille, FR", 43.2965, 5.3698}, "germanywestcentral": {"Frankfurt, DE", 50.1109, 8.6821}, "germanynorth": {"Berlin, DE", 52.52, 13.405},
	"switzerlandnorth": {"Zurich, CH", 47.3769, 8.5417}, "switzerlandwest": {"Geneva, CH", 46.2044, 6.1432}, "norwayeast": {"Oslo, NO", 59.9139, 10.7522}, "norwaywest": {"Stavanger, NO", 58.9699, 5.7331},
	"swedencentral": {"Gävle, SE", 60.6749, 17.1413}, "polandcentral": {"Warsaw, PL", 52.2297, 21.0122}, "italynorth": {"Milan, IT", 45.4642, 9.19}, "spaincentral": {"Madrid, ES", 40.4168, -3.7038},
	"austriaeast": {"Vienna, AT", 48.2082, 16.3738}, "belgiumcentral": {"Brussels, BE", 50.8503, 4.3517}, "denmarkeast": {"Copenhagen, DK", 55.6761, 12.5683},
	"uaenorth": {"Dubai, AE", 25.2048, 55.2708}, "uaecentral": {"Abu Dhabi, AE", 24.4539, 54.3773}, "qatarcentral": {"Doha, QA", 25.2854, 51.531}, "israelcentral": {"Tel Aviv, IL", 32.0853, 34.7818},
	"southafricanorth": {"Johannesburg, ZA", -26.2041, 28.0473}, "southafricawest": {"Cape Town, ZA", -33.9249, 18.4241},
	"eastasia": {"Hong Kong, HK", 22.3193, 114.1694}, "southeastasia": {"Singapore, SG", 1.3521, 103.8198}, "japaneast": {"Tokyo, JP", 35.6762, 139.6503}, "japanwest": {"Osaka, JP", 34.6937, 135.5023},
	"koreacentral": {"Seoul, KR", 37.5665, 126.978}, "koreasouth": {"Busan, KR", 35.1796, 129.0756}, "taiwannorth": {"Taipei, TW", 25.033, 121.5654},
	"australiaeast": {"Sydney, AU", -33.8688, 151.2093}, "australiasoutheast": {"Melbourne, AU", -37.8136, 144.9631}, "australiacentral": {"Canberra, AU", -35.2809, 149.13}, "australiacentral2": {"Canberra, AU", -35.2809, 149.13},
	"newzealandnorth": {"Auckland, NZ", -36.8485, 174.7633}, "centralindia": {"Pune, IN", 18.5204, 73.8567}, "southindia": {"Chennai, IN", 13.0827, 80.2707}, "westindia": {"Mumbai, IN", 19.076, 72.8777},
	"jioindiawest": {"Jamnagar, IN", 22.4707, 70.0577}, "jioindiacentral": {"Nagpur, IN", 21.1458, 79.0882}, "indonesiacentral": {"Jakarta, ID", -6.2088, 106.8456}, "malaysiawest": {"Kuala Lumpur, MY", 3.139, 101.6869},
	"mexicocentral": {"Querétaro, MX", 20.5888, -100.3899}, "chilecentral": {"Santiago, CL", -33.4489, -70.6693},
}

// Oracle names regions by city: us-ashburn-1, eu-frankfurt-1. The middle
// token is looked up here.
var ociCities = map[string]place{
	"ashburn": {"Ashburn, VA, US", 39.0438, -77.4874}, "phoenix": {"Phoenix, AZ, US", 33.4484, -112.074}, "sanjose": {"San Jose, CA, US", 37.3382, -121.8863}, "chicago": {"Chicago, IL, US", 41.8781, -87.6298},
	"toronto": {"Toronto, ON, CA", 43.6532, -79.3832}, "montreal": {"Montreal, QC, CA", 45.5017, -73.5673}, "saopaulo": {"São Paulo, BR", -23.5505, -46.6333}, "vinhedo": {"Vinhedo, BR", -23.0298, -46.9754},
	"santiago": {"Santiago, CL", -33.4489, -70.6693}, "valparaiso": {"Valparaíso, CL", -33.0472, -71.6127}, "bogota": {"Bogotá, CO", 4.711, -74.0721}, "queretaro": {"Querétaro, MX", 20.5888, -100.3899}, "monterrey": {"Monterrey, MX", 25.6866, -100.3161},
	"london": {"London, GB", 51.5072, -0.1276}, "cardiff": {"Cardiff, GB", 51.4816, -3.1791}, "frankfurt": {"Frankfurt, DE", 50.1109, 8.6821}, "amsterdam": {"Amsterdam, NL", 52.3676, 4.9041}, "zurich": {"Zurich, CH", 47.3769, 8.5417},
	"madrid": {"Madrid, ES", 40.4168, -3.7038}, "marseille": {"Marseille, FR", 43.2965, 5.3698}, "milan": {"Milan, IT", 45.4642, 9.19}, "paris": {"Paris, FR", 48.8566, 2.3522}, "stockholm": {"Stockholm, SE", 59.3293, 18.0686}, "jovanovac": {"Belgrade, RS", 44.7866, 20.4489},
	"dubai": {"Dubai, AE", 25.2048, 55.2708}, "abudhabi": {"Abu Dhabi, AE", 24.4539, 54.3773}, "jeddah": {"Jeddah, SA", 21.4858, 39.1925}, "riyadh": {"Riyadh, SA", 24.7136, 46.6753}, "jerusalem": {"Jerusalem, IL", 31.7683, 35.2137}, "johannesburg": {"Johannesburg, ZA", -26.2041, 28.0473},
	"mumbai": {"Mumbai, IN", 19.076, 72.8777}, "hyderabad": {"Hyderabad, IN", 17.385, 78.4867}, "singapore": {"Singapore, SG", 1.3521, 103.8198}, "sydney": {"Sydney, AU", -33.8688, 151.2093}, "melbourne": {"Melbourne, AU", -37.8136, 144.9631},
	"tokyo": {"Tokyo, JP", 35.6762, 139.6503}, "osaka": {"Osaka, JP", 34.6937, 135.5023}, "seoul": {"Seoul, KR", 37.5665, 126.978}, "chuncheon": {"Chuncheon, KR", 37.8813, 127.7298}, "batam": {"Batam, ID", 1.1301, 104.0529},
}

// Cities the geofeeds name, keyed "city, cc".
var geofeedCities = map[string]place{
	"amsterdam, nl": {"Amsterdam, NL", 52.3676, 4.9041}, "north bergen, us": {"North Bergen, NJ, US", 40.7912, -74.0121}, "clifton, us": {"Clifton, NJ, US", 40.8584, -74.1638},
	"santa clara, us": {"Santa Clara, CA, US", 37.3541, -121.9552}, "san francisco, us": {"San Francisco, CA, US", 37.7749, -122.4194}, "frankfurt, de": {"Frankfurt, DE", 50.1109, 8.6821},
	"frankfurt am main, de": {"Frankfurt, DE", 50.1109, 8.6821}, "london, gb": {"London, GB", 51.5072, -0.1276}, "singapore, sg": {"Singapore, SG", 1.3521, 103.8198}, "bangalore, in": {"Bangalore, IN", 12.9716, 77.5946},
	"bengaluru, in": {"Bangalore, IN", 12.9716, 77.5946}, "toronto, ca": {"Toronto, ON, CA", 43.6532, -79.3832}, "sydney, au": {"Sydney, AU", -33.8688, 151.2093},
	"richardson, us": {"Richardson, TX, US", 32.9483, -96.7299}, "fremont, us": {"Fremont, CA, US", 37.5485, -121.9886}, "newark, us": {"Newark, NJ, US", 40.7357, -74.1724}, "atlanta, us": {"Atlanta, GA, US", 33.749, -84.388},
	"tokyo, jp": {"Tokyo, JP", 35.6762, 139.6503}, "mumbai, in": {"Mumbai, IN", 19.076, 72.8777}, "stockholm, se": {"Stockholm, SE", 59.3293, 18.0686}, "paris, fr": {"Paris, FR", 48.8566, 2.3522},
	"chennai, in": {"Chennai, IN", 13.0827, 80.2707}, "jakarta, id": {"Jakarta, ID", -6.2088, 106.8456}, "los angeles, us": {"Los Angeles, CA, US", 34.0522, -118.2437}, "miami, us": {"Miami, FL, US", 25.7617, -80.1918},
	"chicago, us": {"Chicago, IL, US", 41.8781, -87.6298}, "seattle, us": {"Seattle, WA, US", 47.6062, -122.3321}, "washington, us": {"Washington, DC, US", 38.9072, -77.0369}, "osaka, jp": {"Osaka, JP", 34.6937, 135.5023},
	"sao paulo, br": {"São Paulo, BR", -23.5505, -46.6333}, "são paulo, br": {"São Paulo, BR", -23.5505, -46.6333}, "madrid, es": {"Madrid, ES", 40.4168, -3.7038}, "milan, it": {"Milan, IT", 45.4642, 9.19},
	"dallas, us": {"Dallas, TX, US", 32.7767, -96.797}, "ashburn, us": {"Ashburn, VA, US", 39.0438, -77.4874}, "melbourne, au": {"Melbourne, AU", -37.8136, 144.9631}, "auckland, nz": {"Auckland, NZ", -36.8485, 174.7633},
	"johannesburg, za": {"Johannesburg, ZA", -26.2041, 28.0473}, "hong kong, hk": {"Hong Kong, HK", 22.3193, 114.1694}, "seoul, kr": {"Seoul, KR", 37.5665, 126.978}, "dublin, ie": {"Dublin, IE", 53.3498, -6.2603},
	"warsaw, pl": {"Warsaw, PL", 52.2297, 21.0122}, "zurich, ch": {"Zurich, CH", 47.3769, 8.5417}, "vienna, at": {"Vienna, AT", 48.2082, 16.3738}, "prague, cz": {"Prague, CZ", 50.0755, 14.4378},
}

// regionPlace turns a feed's region into a place, or says it cannot.
func regionPlace(feed, region string) (place, bool) {
	r := strings.ToLower(strings.TrimSpace(region))
	var p place
	var ok bool
	switch feed {
	case "aws":
		p, ok = awsRegions[r]
	case "gcp":
		p, ok = gcpRegions[r]
	case "azure":
		p, ok = azureRegions[r]
	case "oci":
		parts := strings.Split(r, "-")
		if len(parts) >= 2 {
			p, ok = ociCities[parts[1]]
		}
	case "do", "linode":
		p, ok = geofeedCities[r]
		if !ok {
			// The general site list knows most cities by name.
			city := strings.TrimSpace(strings.Split(r, ",")[0])
			for _, pp := range pops {
				if strings.EqualFold(strings.Split(pp.City, ",")[0], city) {
					p, ok = place{pp.City, pp.Lat, pp.Lon}, true
					break
				}
			}
		}
	}
	return p, ok
}
