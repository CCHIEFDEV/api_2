<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Contacts extends Model
{
    use HasFactory;

    protected $table = 'contacts';

    public $timestamps = true; //by default timestamp false

    protected $fillable = ['name','email','number','message','extra_field','status'];
}
