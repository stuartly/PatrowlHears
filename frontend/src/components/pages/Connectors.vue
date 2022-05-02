<template>
  <v-card
      class="mx-auto"
  >
    <v-toolbar
    color="grey lighten-4"
    >
<!--      <v-app-bar-nav-icon></v-app-bar-nav-icon>-->

      <v-toolbar-title>Connectors</v-toolbar-title>

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
                <v-list-item-title v-text="item.title"></v-list-item-title>

                <v-list-item-subtitle
                    class="text--secondary"
                    v-text="item.headline"
                ></v-list-item-subtitle>

                <v-list-item-subtitle
                >
                  Update Time: {{new Date().toLocaleDateString()}}
                </v-list-item-subtitle>

<!--                <v-list-item-subtitle v-text="item.subtitle"></v-list-item-subtitle>-->
              </v-list-item-content>

              <v-list-item-action>
                <v-switch
                    v-model="item.isActive"
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
</template>

<script>
export default {
  name: "Connectors",
  data: () => ({
    selected: [2],
    items: [
      {
        headline: 'INTERNAL EXPORT FILE',
        title: 'Export File CSV',
        isActive: true,
      },
      {
        headline: 'STREAM',
        title: 'Hygiene',
        isActive: false,
      },
      {
        headline: 'EXTERNAL IMPORTS',
        title: 'Open CTI',
        isActive: true,
      },
      {
        headline: 'INTERNAL ENRICHMENT',
        title: 'IpInfo',
        isActive: true,
      },
      {
        headline: 'EXTERNAL IMPORTS',
        title: 'CVE',
        isActive: false,
      },
    ],
  }),
}
</script>

<style scoped>

</style>
