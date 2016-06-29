var questions = {};
var languages = [];

// TODO: this re should only accept valid js variable names so numbers/letter/underscore
var cleanRe = /[\[\]\/]/g; // regular expression used to clean names with slashes
var cleanReplacement = '_';

var GROUP_TYPE;
var Groups=[];


$(document).ready(function(){
    //alert('doc ready');
  var getFormValueToParse = "/merge/"+ "get_form_info";
  get_form_info(getFormValueToParse);

  // $("#test_json").click(function(){
  //       //alert('testing');
  //       var param_data = {
  //           'submitted_by':'himel',
  //           'fromdate':'2016-03-13',
  //           'todate':'2016-03-13',
  //       }
  //         setfilter_and_execute(param_data);
        
  //     });
});

Question = function(questionData)
{
    this.name = questionData.name;
    this.type = questionData.type;
    this.label = questionData.label;
}

Group = function(group_no,question,response)
{
    this.group_no = group_no;
    this.question = question;
    this.response = response;
}

Question.prototype.getLabel = function(language)
{
    /// if plain string, return
    if(typeof(this.label) == "string")
        return this.label;
    else if(typeof(this.label) == "object")
    {
        if(language && this.label.hasOwnProperty(language))
            return this.label[language];
        else
        {
            var label = null;
            for(key in this.label)
            {
                label = this.label[key];
                break;// break at first instance and return that
            }
            return label;
        }

    }
    // return raw name
    return this.name;
}

function parseQuestions(children, prefix, cleanReplacement)
{
    var idx;
    cleanReplacement = typeof cleanReplacement !== 'undefined' ? cleanReplacement : '_';

    for(idx in children)
    {
        var question = children[idx];
        //@TODO: do we just want to add anything with children, concern could be it item has children and is alos avalid question - if thats possible
        if(question.hasOwnProperty('children') && ( question.type == "note" || question.type == "repeat" || question.type == "group"))
        {
            if((typeof question.label!='undefined')||question.type.toLowerCase() === 'repeat'){
                GROUP_TYPE = question.type;
                //console.log('GROUP_TYPE '+GROUP_TYPE);
            }
            parseQuestions(question.children, ((prefix?prefix:'') + question.name + cleanReplacement));
        }
        else
        {
            // TODO: question class that has accessor mesthods for type, label, language etc
            questions[((prefix?prefix:'') + question.name)] = new Question(question);
        }
    }
}

function parseLanguages(children)
{
    // run through question objects, stop at first question with label object and check it for multiple languages
    for(questionName in children)
    {
        var question = children[questionName];
        if(question.hasOwnProperty("label"))
        {
            var labelProp = question["label"];
            if(typeof(labelProp) == "string")
                languages = ["default"];
            else if(typeof(labelProp) == "object")
            {
                for(key in labelProp)
                {
                    languages.push(key)
                }
            }
            break;
        }
    }
    if (languages.length == 0) {
        languages.push('en');
    }
}

function generateReportData(data, canEdit,isOld,form_id,instance_id)
{   //console.log('data::'+JSON.stringify(data));
    // make sure we have some data, if the id was in valid we would gte a blank array
    if(data)
    {
     
        var cleanData = {};
        /*------custom group data view start---------*/
        // check for group types if it is a group type with no repeat then we do not need to proces it. 
        //console.log('HIMEL group type: '+ GROUP_TYPE);
    if((typeof GROUP_TYPE!='undefined') && GROUP_TYPE!='group'){
         var key;
         var index =0;
         var group_no = 1;
        for(key in data){
            var cleanKey = key.replace(cleanRe, cleanReplacement);
            //console.log('key '+key+'cleanRe: '+cleanRe+' cleankey: '+cleanKey);
          
                    if( key.indexOf("group") >- 1 ){
                    
                    for(var child in data[key]){
                        var childkey;
                       for(var childob in data[key][child]){
                         childkey = childob.toString();
                         //console.log('childkey: '+childkey);
                         childkey = childkey.replace(key,"").replace(cleanRe,"");
                         
                         Groups[index] = new Group(group_no,childkey,(data[key][child][childob]).toString());
                          //console.log('stringified: '+childkey );
                          if( data.hasOwnProperty(childkey) )
                            data[childkey] += ' , '+data[key][child][childob] ;
                        else
                            data[childkey] = data[key][child][childob];
                        index++;
                       }
                       group_no++;
                    }
                    }        
        }
    }
    else if(GROUP_TYPE==="group"){
        var index = 0;
        var group_no = 1;
        for(key in data){
            if( key.indexOf("group") >- 1 ){
               var cleanKey= key.slice(0, key.indexOf("/"));
               var newKey = key.split('/')[1];
               data[newKey] = data[key]; 
            Groups[index] = new Group(group_no,newKey,(data[key]).toString());
            //var cleanKey = key.replace(cleanRe, cleanReplacement);
               //console.log('key '+key+'cleanRe: '+cleanRe+' newkey: '+newKey+ ' data[newKey]'+ data[newKey]);
               index++;
            }
        }
    }

    /*------custom group data view end---------*/
        //console.log('modified data: '+JSON.stringify(data));
        for(key in data)
        {
            var value = data[key];
            var cleanKey = key.replace(cleanRe, cleanReplacement);
            cleanData[cleanKey] = value;
        }
   // console.log(questions);

    var questionwithVal = {};

    var length = Object.keys(questions).length;
    for (var key in questions){
        var value = {};
        var question = questions[key].name;
        value.question_name = questions[key].name;
        value.question_label = questions[key].label;
        value.question_type = questions[key].type;
        value.question_value = cleanData[key];
        //questionwithVal[questions[key].name] =  value;
        questionwithVal[question] =  value;
    }
    setValueToDatabase(form_id,instance_id,questionwithVal);
    //console.log('questionwith value::----------------------------------------------------------------- '+JSON.stringify(questionwithVal));
    }
}

function setValueToDatabase(form_id_string,instance_id,json_val){
    //console.log(JSON.stringify(json_val));
    var param_data = {
            'form_id_string':form_id_string,
            'instance_id':instance_id,
            'json_val':JSON.stringify(json_val),
        }
    $.ajax({
      url:'/merge/setvalue/',
      type:'POST',
      data: param_data,
      dataType: 'json',
      success: function( json ) {
        console.log('returned json:: '+json);
        //reloadReportChart(json,true,true);
      },
      
    });
}

function get_form_info(url_add){
  $.ajax({
      url:url_add,
      type:'GET',
      dataType: 'json',
      success: function( json ) {
        console.log('returned get_form_info:: '+JSON.stringify(json));
        for (var key in json){
          if (json.hasOwnProperty(key)) {
            var userid = json[key].username;
            var form_id_string = json[key].xform_id_string;
            var instance_id = parseInt(key);
          //console.log('instance_id: '+key+' username:'+ json[key].username+' id_string: '+json[key].xform_id_string);
          var formJSONUrl = "/"+userid+"/forms/"+form_id_string+"/form.json";
          var postgresAPIUrl = "/merge/"+userid+"/forms/"+form_id_string+"/get_json/"+instance_id;
          test_json(formJSONUrl,postgresAPIUrl,form_id_string,instance_id);
          }
        }
      },
      
    });
}

function test_json(question_url, data_url,form_id_string,instance_id){
  $.getJSON(question_url)
            .success(function(data){              
              //console.log('form data-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#\n'+JSON.stringify(data));
              parseQuestions(data.children);
              parseLanguages(data.children);
              $.getJSON(data_url)
                  .success(function(data){
                    //console.log(JSON.stringify(data));
                    generateReportData(data, false,true,form_id_string,instance_id);
                  })
          })
            
}
/*
function setfilter_and_execute(filter_json){
    
    $.ajax({
      url:'/merge/get_merge_json/',
      type:'POST',
      data: filter_json,
      dataType: 'json',
      success: function( json ) {
        console.log('returned json:: '+JSON.stringify(json));
      },
      
    });
}
*/

