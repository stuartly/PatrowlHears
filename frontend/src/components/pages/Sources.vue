<template>
  <div>
    <v-card
        class="mx-auto"
    >
      <v-toolbar
          color="grey lighten-4"
      >
        <!--      <v-app-bar-nav-icon></v-app-bar-nav-icon>-->

        <v-toolbar-title>Sources</v-toolbar-title>

        <!--      <v-spacer></v-spacer>-->

        <!--      <v-btn icon>-->
        <!--        <v-icon>mdi-magnify</v-icon>-->
        <!--      </v-btn>-->

        <!--      <v-btn icon>-->
        <!--        <v-icon>mdi-checkbox-marked-circle</v-icon>-->
        <!--      </v-btn>-->
      </v-toolbar>

      <v-list two-line>
        <v-list-item-group
        >
          <template v-for="(item, index) in items">
            <v-list-item :key="item.title">
              <template v-slot:default>
                <v-list-item-content>
                  <v-list-item-title v-text="item.name"></v-list-item-title>

                  <v-list-item-subtitle
                      class="text--secondary"
                      v-text="item.description"
                  ></v-list-item-subtitle>

                  <v-list-item-subtitle
                  >
                    Update Time: {{ new Date().toLocaleDateString() }}
                  </v-list-item-subtitle>

                  <!--                <v-list-item-subtitle v-text="item.subtitle"></v-list-item-subtitle>-->
                </v-list-item-content>

                <v-list-item-action>
                  <v-switch
                      v-model="item.isEnabled"
                      @change="modifySource(index)"
                      inset
                  ></v-switch>
                </v-list-item-action>
              </template>
            </v-list-item>

            <v-divider
                v-if="index < items.length - 1"
                :key="index"
            ></v-divider>
          </template>
        </v-list-item-group>
      </v-list>
    </v-card>

    <v-dialog
        v-model="dialog"
    >
      <v-card width="350" style="position: fixed;margin:0 auto;left:0;right:0;top: 30%">
        <v-card-title class="text-h5 grey lighten-2">
          {{this.alertTitleText}}
        </v-card-title>

        <v-card-text v-if="items[cur_index].isEnabled">
          System will regularly update "{{items[cur_index].name}}" data source at 0:00 every day
        </v-card-text>
        <v-card-text v-else>
          System will no longer update "{{items[cur_index].name}}" data source
        </v-card-text>

        <v-divider></v-divider>

        <v-card-actions>
          <v-spacer></v-spacer>
          <v-btn
              color="secondary"
              text
              @click="cancel"
          >
            cancel
          </v-btn>
          <v-btn
              color="primary"
              text
              @click="confirm"
          >
            confirm
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<script>
export default {
  name: "Sources",
  data: () => ({
    selected: [2],
    items: [
      // {
      //   description: 'INTERNAL EXPORT FILE',
      //   name: 'Export File CSV',
      //   isEnabled: true,
      // },
      // {
      //   description: 'STREAM',
      //   name: 'Hygiene',
      //   isEnabled: false,
      // },
      // {
      //   description: 'EXTERNAL IMPORTS',
      //   name: 'Open CTI',
      //   isEnabled: true,
      // },
      // {
      //   description: 'INTERNAL ENRICHMENT',
      //   name: 'IpInfo',
      //   isEnabled: true,
      // },
      {
        description: 'EXTERNAL IMPORTS',
        name: 'CVE',
        isEnabled: false,
      },
    ],
    cur_index: 0,
    dialog: false,
  }),
  methods: {
    modifySource(index) {
      this.cur_index = index
      this.dialog = true
      // console.log(index)
    },
    cancel(){
      let item = this.items[this.cur_index]
      this.dialog = false
      setTimeout(()=>{item.isEnabled = !item.isEnabled;}, 200);
    },
    confirm(){
      let item = this.items[this.cur_index]
      console.log(item)
      this.$api.post('/api/data/source/modify', {
        name: item.name,
        isEnabled: item.isEnabled
      }).then(res => {
        console.log("success")
      })
      this.dialog = false
    },
    updateSource(index) {
      this.$api.get('/api/data/source/info').then(res => {
        console.log(res.data)
        this.items = res.data
      })
    },
  },
  computed:{
    alertTitleText(){
      let item = this.items[this.cur_index]
      if (item.isEnabled){
        return "Turn On Data Source"
      }else {
        return "Turn Off Data Source"
      }
    },
  },
  mounted() {
    this.updateSource()
  }
}
</script>

<style scoped>

</style>
