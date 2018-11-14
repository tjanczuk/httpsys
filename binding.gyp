{
  'targets': [
    {
      'target_name': 'httpsys',
      'sources': [ 
      	'src/httpsys.cc'
      ],
	  "include_dirs": [
	    "<!(node -e \"require('nan')\")"
	  ]
    }
  ]
} 
