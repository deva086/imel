var criteria_counts = [];
$(document).on('change', '.audio_filters', function() { //================================== start document change function
    var criteria_id = $(this).attr("id");
    var count = criteria_id.charAt(criteria_id.length-1);
    var criteria_index = $(this).val(); // filter data array index
    if(criteria_index !== 'custom'){
        var html_type = filtered_data[criteria_index].type;
        var key = filtered_data[criteria_index].xpath;
        if(html_type == "select one"){
            var select_options = filtered_data[criteria_index].children;
            var crosstab = {} ;
            crosstab.span = select_options.length;
            crosstab.label = filtered_data[criteria_index].label;
            crosstab.options = select_options;
            crosstab.key = key;
            criteria_counts[parseInt(count)] = crosstab;        
        }
    }
});
var response_data = [];
$("#preview").click(function(){
    var select1 = $('#criteria1').val();
    var select2 = $('#criteria2').val();
    if (select1 !== 'custom' && select2 !== 'custom') {
        $.ajax({
           type: "GET",
           url:"/usermodule/ajax-reponse/",
           data: {key1: criteria_counts[1].key,key2: criteria_counts[2].key},
           success: function(data){
               response_data = data;
               generate_table();
           },
           error: function(){
               console.log("Ajax Error")
           }
        }) // end-ajax    
    }else{
        $('.audio-table').empty();
    } 
});

$( '.audio-table' ).on( 'click', 'a', function () { 
    var criteria_key_1 = $(this).attr("search_key1");
    var criteria_key_2 = $(this).attr("search_key2");
    var criteria_value_1 = $(this).attr("search_value1");
    var criteria_value_2 = $(this).attr("search_value2");
    var audio_query = "{ ";
    audio_query += '"' + criteria_key_1 + '" : "'+ criteria_value_1 + '"';
    audio_query += ' , "' + criteria_key_2 + '" : "'+ criteria_value_2 + '"';
    audio_query += " }";
    var request_url = mongoAPIUrl+"?query="+audio_query;
    // var locked_user_id = $(this).attr("data-id");
    // var div = $("#alert-message");  
    var base_url = window.location.protocol+"//"+window.location.host + "/media/" ;
    var image_list = [];
    var image_set = new Set();
    var audio_list = [];
    var audio_set = new Set();
    $.ajax({
       type: "GET",
       url:request_url,
       // data: {key1: criteria_counts[1].key,key2: criteria_counts[2].key},
       success: function(data){
           data.forEach(function(submission) {

               var image_count = 0;
               var audio_count = 0;
               // loops through each attachment of a submission
               submission._attachments.forEach(function(attachment) {
                  var media_path = base_url + attachment.filename ;
                  var media_name_index = attachment.filename.lastIndexOf("/") + 1;
                  var media_name = attachment.filename.substring(media_name_index);
                  var media_label = get_label(media_name,data);
                  if(attachment.mimetype.startsWith('image')){
                      var media_object = {'media_name':media_name,'media_path':media_path,'media_count':image_count,'media_label':media_label};
                      image_list.push(media_object);
                      image_set.add(image_count);
                      image_count += 1 ;
                  }else if(attachment.mimetype.startsWith('audio')){
                      var media_object = {'media_name':media_name,'media_path':media_path,'media_count':audio_count,'mimetype':attachment.mimetype,'media_label':media_label};
                      audio_list.push(media_object);
                      audio_set.add(media_label);
                      audio_count += 1 ;
                      // console.log(media_object)
                  }
              });
           });
           
           // if (typeof generate_gallery == 'function') { 
           //     generate_gallery(image_list,image_set);
           // }
           if (typeof generate_audio == 'function') { 
               generate_audio(audio_list,audio_set);
           }
       },
       error: function(){
           console.log("Ajax Error")
       }
    }) // end-ajax
    return false; 
 });
    // // var criteria_key_1 = $(this).attr("search_key1");
    // // var criteria_key_2 = $(this).attr("search_key2");
    // var criteria_value_1 = $(this).attr("search_value1");
    // var criteria_value_2 = $(this).attr("search_value2");
    // var audio_query = "{ ";
    // audio_query += criteria_key_1 + ":"+ criteria_value_1;
    // audio_query += "," + criteria_key_2 + ":"+ criteria_value_2;
    // audio_query += " }";
    // var request_url = mongoAPIUrl+"?query="+audio_query;
    // // var locked_user_id = $(this).attr("data-id");
    // // var div = $("#alert-message");  
    // $.ajax({
    //    type: "GET",
    //    url:request_url,
    //    // data: {key1: criteria_counts[1].key,key2: criteria_counts[2].key},
    //    success: function(data){
    //        // response_data = data;
    //        console.log(data);
    //        // generate_table();
    //    },
    //    error: function(){
    //        console.log("Ajax Error")
    //    }
    // }) // end-ajax
    // return false; 
// }
// });


function generate_table() {
    var colspan_count = criteria_counts[2].span*4 + 1;
    if(criteria_counts[2].label !== null && typeof criteria_counts[2].label === 'object'){
        var horizontal_question = criteria_counts[2].label.default;
    }else{
        var horizontal_question = criteria_counts[2].label;
    }
    if(criteria_counts[1].label !== null && typeof criteria_counts[1].label === 'object'){
        var vertical_question = criteria_counts[1].label.default;
    }else{
        var vertical_question = criteria_counts[1].label;
    }
    // var horizontal_question = criteria_counts[2].label;
    // var vertical_question = criteria_counts[1].label;
    var table = '<table class="table" border="1" id="audio_table">';
    table += '<tr>';
    table += '<th colspan="'+colspan_count+'">Data Display Format (aggregate)</th>';
    table += '</tr>';

    table += '<tr>';
    table += '<th>Questions</th>';
    table += '<th colspan="'+(colspan_count-1)+'">'+ horizontal_question +'</th>';
    table += '</tr>';

    table += '<tr>';
    table += '<th rowspan="2">'+ vertical_question +'</th>';
    criteria_counts[2].options.forEach(function(option){
        if(option.label !== null && typeof option.label === 'object'){
            table += '<th colspan="4">'+ option.label.default +'</th>';
        }else{
            table += '<th colspan="4">'+ option.label +'</th>';
        }
    });
    table += '</tr>';

    table += '<tr>';
    criteria_counts[2].options.forEach(function(option){
        table += '<th>Current</th>';
        table += '<th>Previous</th>';
        table += '<th>Percentage Change</th>';
        table += '<th>Total</th>';
    });
    table += '</tr>';
    var search_key1 = criteria_counts[1].key;
    var search_key2 = criteria_counts[2].key;
    var k1_count = '';
    var k2_count = '';
    criteria_counts[1].options.forEach(function(option){
        table += '<tr>';
        if(option.label !== null && typeof option.label === 'object'){
            table += '<th>'+ option.label.default +'</th>';
        }else{
            table += '<th>'+ option.label +'</th>';
        }
        k1_count = option.name.toString();
        criteria_counts[2].options.forEach(function(option2){
            k2_count = option2.name.toString();
            table += '<td><a href="#" class="search" search_key1="'+search_key1+'" search_key2="'+search_key2+'" search_value1="'+k1_count+'" search_value2="'+k2_count+'" >'+get_count(k1_count,k2_count)+'</a></td>';
            // table += '<td><a href="#" onclick="get_audio('+search_key1+','+search_key2+','+k1_count+','+k2_count');return false;" class="search" search_key1="'+search_key1+'" search_key2="'+search_key2+'" search_value1="'+k1_count+'" search_value2="'+k2_count+'" >'+get_count(k1_count,k2_count)+'</a></td>';
            
            table += '<td>0</td>';
            table += '<td>0</td>';
            table += '<td>0</td>';
        });
        table += '</tr>';
    });
//     global_audio_list.forEach(function(audio){
//         if ( filter_value === String(audio.media_count)){
//             // var img = '<a href="'+image.media_path+'" title="'+image.media_name+'" class="'+ image.media_count +'" data-gallery>';
//             // img += '<img src="'+image.media_path+'" width="100px" height="100px" class="'+ image.media_count +'" alt="'+image.media_name+'">';
//             // img += '</a>';
//             // $("#links").append(img);
//             table += '<tr>' ;
//             table += '<td>'+audio.media_name+'</td>' ;
//             // table += '<td><audio controls><source src="'+audio.media_path+'" type="'+audio.mimetype+'">Your browser does not support the audio element.</audio></td>' ;
//             table += '<td><audio controls><source src="'+audio.media_path+'" type="audio/mpeg">Your browser does not support the audio element.</audio></td>' ;
//             table += '<td><a href="'+audio.media_path+'" download="'+audio.media_name+'" target="_blank">'+audio.media_name+'</a></td>' ;
//             table += '</tr>' ;
//         }
//     });
    table += '</table>' ;
    $('.audio-table').empty();
    $('.audio-table').append(table);
}


function get_count(key1, key2) {
    var count = 0;
    response_data.forEach(function(obj){
        if (obj.id.key1 === key1 && obj.id.key2 === key2) {
            count = obj.count;
        };
    });
    return count;
}


$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
            var csrftoken = getCookie('csrftoken');
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        }
    }
});

function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie != '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) == (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}